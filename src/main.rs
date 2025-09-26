use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use flate2::Compression;
use flate2::read::{ZlibDecoder, ZlibEncoder};
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use md5;
use memmap2::MmapOptions;
use std::fs;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::process::Command as ProcessCommand;
use thiserror::Error;

// Custom error types for better error handling
#[derive(Error, Debug)]
pub enum FirmwareError {
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Command Error: {0}")]
    CommandError(String),

    #[error("Parse Error: {0}")]
    ParseError(String),

    #[error("Validation Error: {0}")]
    ValidationError(String),

    #[error("Not Implemented: {0}")]
    NotImplemented(String),

    #[error("Size Error: {0}")]
    SizeError(String),
}

// Progress and logging utility
struct ProgressLogger {
    verbose: bool,
}

impl ProgressLogger {
    fn new(verbose: bool) -> Self {
        ProgressLogger { verbose }
    }

    fn info(&self, msg: &str) {
        info!("{}", msg);
    }

    fn warn(&self, msg: &str) {
        warn!("{}", msg);
    }

    fn error(&self, msg: &str) {
        error!("{}", msg);
    }

    fn verbose(&self, msg: &str) {
        if self.verbose {
            debug!("{}", msg);
        }
    }

    fn progress(&self, msg: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap(),
        );
        pb.set_message(msg.to_string());
        pb
    }
}

#[derive(Parser)]
#[command(name = "re300")]
#[command(about = "TP-Link RE300 firmware analysis and modification tool")]
struct Args {
    #[arg(long, help = "Verbose output for debugging")]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Read flash memory using flashrom
    #[command(name = "readflash")]
    ReadFlash {
        #[arg(help = "Flash chip model")]
        chip: String,

        #[arg(help = "Programmer to use")]
        programmer: String,

        #[arg(
            short,
            long,
            help = "Output file path",
            default_value = "flash_dump.bin"
        )]
        output: String,
    },

    /// Write flash memory using flashrom
    #[command(name = "writeflash")]
    WriteFlash {
        #[arg(short, help = "Flash chip model", default_value = "EN25QH64A")]
        chip: String,

        #[arg(short, help = "Programmer to use", default_value = "ch341a_spi")]
        programmer: String,

        #[arg(help = "Input file to write to flash")]
        file: String,
    },

    /// Analyze flash dump file
    #[command(name = "analysedump")]
    AnalyseDump {
        #[arg(help = "Flash dump file to analyze")]
        file: String,

        #[arg(
            long,
            help = "Output directory for carved partitions",
            default_value = "carved_partitions"
        )]
        carve_dir: String,
    },

    /// Patch flash dump with modified filesystem
    #[command(name = "patchdump")]
    PatchDump {
        #[arg(help = "Input flash dump file")]
        file: String,

        #[arg(short, long, help = "Output file for patched dump")]
        output: String,

        #[arg(
            long,
            help = "Custom root password for filesystem modification",
            default_value = "root"
        )]
        root_password: String,
    },

    /// Decrypt configuration partition
    #[command(name = "decryptconfig")]
    DecryptConfig {
        #[arg(help = "Input configuration file")]
        file: String,

        #[arg(short, long, help = "Output decrypted file")]
        output: String,
    },

    /// Encrypt configuration partition
    #[command(name = "encryptconfig")]
    EncryptConfig {
        #[arg(help = "Input decrypted file")]
        file: String,

        #[arg(short, long, help = "Output encrypted file")]
        output: String,
    },

    /// Build flash image with custom U-Boot, initramfs kernel, and radio
    #[command(name = "buildflash")]
    BuildFlash {
        #[arg(help = "U-Boot SPL binary file")]
        uboot: String,

        #[arg(help = "Initramfs kernel file")]
        kernel: String,

        #[arg(
            short,
            long,
            help = "Radio partition file (optional, extracts from flash_dump.bin if not provided)"
        )]
        radio: Option<String>,

        #[arg(
            short,
            long,
            help = "Config partition file (optional, extracts from flash_dump.bin if not provided)"
        )]
        config: Option<String>,

        #[arg(long, help = "Create uImage header for U-Boot bootm compatibility")]
        create_uimage: bool,

        #[arg(
            long,
            help = "Place kernel after U-Boot environment (at 0x40000) to avoid conflicts"
        )]
        skip_env: bool,
    },

    /// Build flash image with separate kernel and rootfs binaries
    #[command(name = "buildseparate")]
    BuildSeparate {
        #[arg(help = "U-Boot SPL binary file")]
        uboot: String,

        #[arg(help = "Kernel binary file (FIT image)")]
        kernel: String,

        #[arg(help = "Root filesystem binary file (squashfs)")]
        rootfs: String,

        #[arg(
            short,
            long,
            help = "Radio partition file (optional, extracts from flash_dump.bin if not provided)"
        )]
        radio: Option<String>,

        #[arg(long, help = "Create uImage header for kernel compatibility")]
        create_uimage: bool,
    },
}

#[repr(C, packed)]
#[derive(Debug)]
struct FlashImage {
    fs_uboot: [u8; 0x20000],       // 0x00000000 - 0x00020000: fs-uboot
    os_image: [u8; 0xE0000],       // 0x00020000 - 0x00100000: os-image
    file_system: [u8; 0x6C0000],   // 0x00100000 - 0x007C0000: file-system
    partition_table: [u8; 0x2000], // 0x007C0000 - 0x007C2000: partition-table
    default_mac: [u8; 0x20],       // 0x007C2000 - 0x007C2020: default-mac
    _pad1: [u8; 0xE0],             // 0x007C2020 - 0x007C2100: padding
    pin: [u8; 0x20],               // 0x007C2100 - 0x007C2120: pin
    _pad2: [u8; 0xFE0],            // 0x007C2120 - 0x007C3100: padding
    product_info: [u8; 0x1000],    // 0x007C3100 - 0x007C4100: product-info
    _pad3: [u8; 0x100],            // 0x007C4100 - 0x007C4200: padding
    soft_version: [u8; 0x1000],    // 0x007C4200 - 0x007C5200: soft-version
    support_list: [u8; 0x1000],    // 0x007C5200 - 0x007C6200: support-list
    profile: [u8; 0x8000],         // 0x007C6200 - 0x007CE200: profile
    config_info: [u8; 0x400],      // 0x007CE200 - 0x007CE600: config-info
    _pad4: [u8; 0x1A00],           // 0x007CE600 - 0x007D0000: padding
    user_config: [u8; 0x10000],    // 0x007D0000 - 0x007E0000: user-config
    default_config: [u8; 0x10000], // 0x007E0000 - 0x007F0000: default-config
    radio: [u8; 0x10000],          // 0x007F0000 - 0x00800000: radio
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose { "debug" } else { "info" };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level)).init();

    // Create progress logger
    let logger = ProgressLogger::new(args.verbose);

    logger.info(&format!(
        "Starting RE300 firmware analysis tool v{}",
        env!("CARGO_PKG_VERSION")
    ));

    match args.command {
        Command::ReadFlash {
            chip,
            programmer,
            output,
        } => {
            logger.info(&format!(
                "Reading flash: chip={}, programmer={}, output={}",
                chip, programmer, output
            ));
            let should_dump = check_file_exists(&output);
            if should_dump {
                read_flash(&chip, &programmer, &output);
            }
        }

        Command::WriteFlash {
            chip,
            programmer,
            file,
        } => {
            logger.info(&format!(
                "Writing flash: chip={}, programmer={}, file={}",
                chip, programmer, file
            ));
            if !Path::new(&file).exists() {
                logger.error(&format!("Input file does not exist: {}", file));
                std::process::exit(1);
            }
            write_flash(&chip, &programmer, &file);
        }

        Command::AnalyseDump { file, carve_dir } => {
            logger.info(&format!(
                "Analyzing dump: file={}, carve_dir={}",
                file, carve_dir
            ));
            if !Path::new(&file).exists() {
                logger.error(&format!("Dump file does not exist: {}", file));
                std::process::exit(1);
            }

            // Create carve directory
            if let Err(e) = fs::create_dir_all(&carve_dir) {
                logger.error(&format!(
                    "Cannot create carve directory {}: {}",
                    carve_dir, e
                ));
                std::process::exit(1);
            }

            analyze_dump(&file, false, &carve_dir, &logger)?;
        }

        Command::PatchDump {
            file,
            output,
            root_password,
        } => {
            logger.info(&format!(
                "Patching dump: file={}, output={}, password={}",
                file, output, root_password
            ));
            if !Path::new(&file).exists() {
                logger.error(&format!("Input file does not exist: {}", file));
                std::process::exit(1);
            }
            analyze_dump(&file, true, "carved_partitions", &logger)?;
        }

        Command::DecryptConfig { file, output } => {
            logger.info(&format!(
                "Decrypting config: file={}, output={}",
                file, output
            ));
            if !Path::new(&file).exists() {
                logger.error(&format!("Input file does not exist: {}", file));
                std::process::exit(1);
            }
            decrypt_config(&file, &output, &logger)?;
        }

        Command::EncryptConfig { file, output } => {
            logger.info(&format!(
                "Encrypting config: file={}, output={}",
                file, output
            ));
            if !Path::new(&file).exists() {
                logger.error(&format!("Input file does not exist: {}", file));
                std::process::exit(1);
            }
            encrypt_config(&file, &output, &logger)?;
        }

        Command::BuildFlash {
            uboot,
            kernel,
            radio,
            config,
            create_uimage,
            skip_env,
        } => {
            logger.info(&format!("Building flash image: uboot={}, kernel={}, radio={:?}, config={:?}, create_uimage={}, skip_env={}", uboot, kernel, radio, config, create_uimage, skip_env));
            if !Path::new(&uboot).exists() {
                logger.error(&format!("U-Boot file does not exist: {}", uboot));
                std::process::exit(1);
            }
            if !Path::new(&kernel).exists() {
                logger.error(&format!("Kernel file does not exist: {}", kernel));
                std::process::exit(1);
            }
            if let Some(radio_path) = &radio {
                if !Path::new(radio_path).exists() {
                    logger.error(&format!("Radio file does not exist: {}", radio_path));
                    std::process::exit(1);
                }
            }
            if let Some(config_path) = &config {
                if !Path::new(config_path).exists() {
                    logger.error(&format!("Config file does not exist: {}", config_path));
                    std::process::exit(1);
                }
            }
            build_flash_with_components(
                &uboot,
                &kernel,
                radio.as_deref(),
                config.as_deref(),
                create_uimage,
                skip_env,
            )?;
        }

        Command::BuildSeparate {
            uboot,
            kernel,
            rootfs,
            radio,
            create_uimage,
        } => {
            logger.info(&format!("Building flash with separate components: uboot={}, kernel={}, rootfs={}, radio={:?}, create_uimage={}", uboot, kernel, rootfs, radio, create_uimage));
            if !Path::new(&uboot).exists() {
                logger.error(&format!("U-Boot file does not exist: {}", uboot));
                std::process::exit(1);
            }
            if !Path::new(&kernel).exists() {
                logger.error(&format!("Kernel file does not exist: {}", kernel));
                std::process::exit(1);
            }
            if !Path::new(&rootfs).exists() {
                logger.error(&format!("Rootfs file does not exist: {}", rootfs));
                std::process::exit(1);
            }
            if let Some(radio_path) = &radio {
                if !Path::new(radio_path).exists() {
                    logger.error(&format!("Radio file does not exist: {}", radio_path));
                    std::process::exit(1);
                }
            }
            build_flash_with_separate_components(
                &uboot,
                &kernel,
                &rootfs,
                radio.as_deref(),
                create_uimage,
                &logger,
            )?;
        }
    }

    Ok(())
}

fn carve_partitions(flash_image: &FlashImage, output_dir: &str) {
    println!("\n=== Carving Partitions ===");

    println!("  Output directory: {}", output_dir);

    let uboot_path = format!("{}/fs-uboot.bin", output_dir);
    match fs::write(&uboot_path, &flash_image.fs_uboot) {
        Ok(_) => println!("  Carved fs-uboot to: {}", uboot_path),
        Err(e) => eprintln!("  Failed to carve fs-uboot: {}", e),
    }

    let os_image_path = format!("{}/os-image.bin", output_dir);
    match fs::write(&os_image_path, &flash_image.os_image) {
        Ok(_) => println!("  Carved os-image to: {}", os_image_path),
        Err(e) => eprintln!("  Failed to carve os-image: {}", e),
    }

    let filesystem_path = format!("{}/file-system.bin", output_dir);
    match fs::write(&filesystem_path, &flash_image.file_system) {
        Ok(_) => println!("  Carved file-system to: {}", filesystem_path),
        Err(e) => eprintln!("  Failed to carve file-system: {}", e),
    }

    println!("  All main partitions carved to: {}/", output_dir);
}

fn modify_filesystem_and_rebuild(flash_image: &FlashImage) -> Result<Vec<u8>, anyhow::Error> {
    println!("\n=== Modifying Filesystem and Rebuilding Image ===");

    let work_dir = "filesystem_work";
    let extracted_dir = format!("{}/extracted", work_dir);
    let filesystem_path = format!("{}/file-system.bin", work_dir);

    let cleanup = || {
        if Path::new(&work_dir).exists() {
            let _ = fs::remove_dir_all(&work_dir);
        }
    };

    if let Err(e) = fs::create_dir_all(&work_dir) {
        cleanup();
        return Err(e.into());
    }

    if let Err(e) = fs::write(&filesystem_path, &flash_image.file_system) {
        cleanup();
        return Err(e.into());
    }
    println!("  Wrote filesystem partition to: {}", filesystem_path);

    println!("  Extracting squashfs filesystem...");
    let unsquash_output = match ProcessCommand::new("unsquashfs")
        .args(&["-d", &extracted_dir, &filesystem_path])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            cleanup();
            return Err(e.into());
        }
    };

    if !unsquash_output.status.success() {
        cleanup();
        return Err(anyhow!(format!(
            "unsquashfs failed: {}",
            String::from_utf8_lossy(&unsquash_output.stderr)
        )));
    }

    let shadow_path = format!("{}/etc/shadow", extracted_dir);
    if Path::new(&shadow_path).exists() {
        println!("  Modifying shadow file to set root password...");
        let shadow_content = match fs::read_to_string(&shadow_path) {
            Ok(content) => content,
            Err(e) => {
                cleanup();
                return Err(e.into());
            }
        };

        // Replace root line with password "root" (hash: $1$root$9gr5KxwuEdiI80GtIzd.U0)
        let new_shadow = shadow_content
            .lines()
            .map(|line| {
                if line.starts_with("root:") {
                    "root:$1$root$9gr5KxwuEdiI80GtIzd.U0:0:0:99999:7:::"
                } else {
                    line
                }
            })
            .collect::<Vec<_>>()
            .join("\n");

        if let Err(e) = fs::write(&shadow_path, new_shadow) {
            cleanup();
            return Err(e.into());
        }
        println!("  Modified root password in shadow file");
    } else {
        println!("  Warning: shadow file not found at {}", shadow_path);
    }

    let new_filesystem_path = format!("{}/new-file-system.bin", work_dir);
    println!("  Recompressing filesystem with xz and -no-duplicates...");

    let mksquashfs_output = match ProcessCommand::new("mksquashfs")
        .args(&[
            &extracted_dir,
            &new_filesystem_path,
            "-comp",
            "xz",
            "-no-duplicates",
            "-b",
            "1048576", // 1MB block size
        ])
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            cleanup();
            return Err(e.into());
        }
    };

    if !mksquashfs_output.status.success() {
        cleanup();
        return Err(anyhow!(format!(
            "mksquashfs failed: {}",
            String::from_utf8_lossy(&mksquashfs_output.stderr)
        )));
    }

    let new_fs_data = match fs::read(&new_filesystem_path) {
        Ok(data) => data,
        Err(e) => {
            cleanup();
            return Err(e.into());
        }
    };
    const MAX_SIZE: usize = 0x6C0000;

    if new_fs_data.len() > MAX_SIZE {
        cleanup();
        return Err(anyhow!(format!(
            "New filesystem too large: {} bytes > {} bytes",
            new_fs_data.len(),
            MAX_SIZE
        )));
    }

    println!(
        "  New filesystem size: {} bytes (max: {} bytes)",
        new_fs_data.len(),
        MAX_SIZE
    );

    println!("  Building new flash image...");
    let mut new_image = Vec::new();

    new_image.extend_from_slice(&flash_image.fs_uboot);

    new_image.extend_from_slice(&flash_image.os_image);

    new_image.extend_from_slice(&new_fs_data);

    let fs_padding_needed = MAX_SIZE - new_fs_data.len();
    if fs_padding_needed > 0 {
        new_image.extend(vec![0xFF; fs_padding_needed]);
        println!("  Padded filesystem with {} bytes", fs_padding_needed);
    }

    let remaining_offset = 0x20000 + 0xE0000 + 0x6C0000;
    let original_image_bytes = unsafe {
        std::slice::from_raw_parts(
            flash_image as *const _ as *const u8,
            std::mem::size_of::<FlashImage>(),
        )
    };

    if original_image_bytes.len() > remaining_offset {
        new_image.extend_from_slice(&original_image_bytes[remaining_offset..]);
    }

    let new_image_path = "flash_dump_modified.bin";
    if let Err(e) = fs::write(new_image_path, &new_image) {
        cleanup();
        return Err(e.into());
    }
    println!("  New flash image written to: {}", new_image_path);

    cleanup();

    Ok(new_image)
}

fn analyze_partition(data: &[u8], name: &str) {
    println!("{} partition size: {} bytes", name, data.len());

    let all_zero = data.iter().all(|&x| x == 0x00);
    let all_ff = data.iter().all(|&x| x == 0xFF);

    if all_zero {
        println!("  Status: Empty (all zeros)");
    } else if all_ff {
        println!("  Status: Erased (all 0xFF)");
    } else {
        println!("  Status: Contains data");
        // Show first few bytes as hex
        let preview_len = std::cmp::min(16, data.len());
        print!("  First {} bytes: ", preview_len);
        for &byte in &data[..preview_len] {
            print!("{:02X} ", byte);
        }
        println!();
    }
}

fn analyze_os_image(data: &[u8]) {
    println!("OS Image partition size: {} bytes", data.len());
}

fn analyze_config_partitions(flash_image: &FlashImage) {
    print!("  Default MAC: ");
    if flash_image
        .default_mac
        .iter()
        .all(|&x| x == 0x00 || x == 0xFF)
    {
        println!("Empty");
    } else {
        for (i, &byte) in flash_image.default_mac[..6].iter().enumerate() {
            if i > 0 {
                print!(":");
            }
            print!("{:02X}", byte);
        }
        println!();
    }

    print!("  PIN: ");
    let pin_end = flash_image
        .pin
        .iter()
        .position(|&x| x == 0x0A)
        .unwrap_or(32);
    let pin_str = String::from_utf8_lossy(&flash_image.pin[..pin_end]);
    println!("{}", pin_str);

    print!("  Product Info: ");
    let product_end = flash_image
        .product_info
        .iter()
        .position(|&x| x == 0x0A)
        .unwrap_or(std::cmp::min(64, flash_image.product_info.len()));
    let product_str = String::from_utf8_lossy(&flash_image.product_info[..product_end]);
    println!("{}", product_str);

    print!("  Software Version (hex): ");
    for &byte in &flash_image.soft_version[..std::cmp::min(16, flash_image.soft_version.len())] {
        print!("{:02X} ", byte);
    }
    println!();
}

fn check_file_exists(file_path: &str) -> bool {
    if fs::metadata(file_path).is_ok() {
        print!(
            "File '{}' already exists. Do you want to redump? (y/N): ",
            file_path
        );
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();

        let response = input.trim().to_lowercase();
        response == "y" || response == "yes"
    } else {
        true
    }
}

fn read_flash(chip: &str, programmer: &str, output: &str) {
    println!(
        "Reading flash with chip: {}, programmer: {}, output: {}",
        chip, programmer, output
    );
    ProcessCommand::new("flashrom")
        .args(&["-p", programmer, "-c", chip, "-r", output])
        .status()
        .expect("failed to execute flashrom");
}

fn analyze_dump(
    file_path: &str,
    modify_fs: bool,
    carve_dir: &str,
    logger: &ProgressLogger,
) -> Result<()> {
    logger.info(&format!("Analyzing dump file: {}", file_path));

    let file = fs::File::open(file_path)?;
    let file_size = file.metadata()?.len();

    let file_data: Box<[u8]> = if file_size > 50 * 1024 * 1024 {
        logger.verbose("Using memory mapping for large file");
        let mmap = unsafe { MmapOptions::new().map(&file)? };
        mmap.to_vec().into_boxed_slice()
    } else {
        logger.verbose("Reading file into memory");
        fs::read(file_path)?.into_boxed_slice()
    };

    logger.verbose(&format!("File size: {} bytes", file_data.len()));

    let pb = logger.progress("Parsing flash image layout...");
    if let Some(flash_image) = parse_bin_simple(&file_data, carve_dir, logger) {
        pb.finish_with_message("Flash image layout parsed successfully");

        if modify_fs {
            let pb = logger.progress("Modifying filesystem...");
            match modify_filesystem_and_rebuild(&flash_image) {
                Ok(_) => {
                    pb.finish_with_message("Successfully modified filesystem and rebuilt image!");
                    logger.info("Modified firmware image saved as 'flash_dump_modified.bin'");
                }
                Err(e) => {
                    pb.finish_with_message("Failed to modify filesystem");
                    logger.error(&format!("Filesystem modification error: {}", e));
                    return Err(e.into());
                }
            }
        }
    } else {
        pb.finish_with_message("Failed to parse flash image layout");
        return Err(FirmwareError::ParseError("Could not parse flash image".to_string()).into());
    }

    logger.info("Running binwalk analysis...");
    let pb = logger.progress("Analyzing with binwalk...");
    let binwalk = binwalk::Binwalk::new();
    let mut result_count = 0;
    for result in binwalk.scan(&file_data) {
        logger.verbose(&format!(
            "Offset: 0x{:X}, Description: {}",
            result.offset, result.description
        ));
        result_count += 1;
    }
    pb.finish_with_message("Binwalk analysis completed");
    logger.info(&format!("Found {} items in binwalk analysis", result_count));

    Ok(())
}

fn parse_bin_simple(
    data: &[u8],
    carve_dir: &str,
    logger: &ProgressLogger,
) -> Option<Box<FlashImage>> {
    logger.verbose(&format!("Data size: {}", data.len()));
    logger.verbose(&format!(
        "Expected FlashImage size: {}",
        std::mem::size_of::<FlashImage>()
    ));

    if data.len() < std::mem::size_of::<FlashImage>() {
        logger.error("Flash dump too small to contain complete image layout");
        return None;
    }

    let flash_image = Box::new(unsafe { std::ptr::read(data.as_ptr() as *const FlashImage) });

    logger.info(&format!(
        "Total image size: {} bytes (0x{:X})",
        data.len(),
        data.len()
    ));

    logger.info("=== U-Boot Partition (0x00000000 - 0x00020000) ===");
    analyze_partition(&flash_image.fs_uboot, "U-Boot");

    logger.info("=== OS Image Partition (0x00020000 - 0x00100000) ===");
    analyze_os_image(&flash_image.os_image);

    logger.info("=== File System Partition (0x00100000 - 0x007C0000) ===");
    analyze_partition(&flash_image.file_system, "File System");

    logger.info("=== Configuration Partitions ===");
    analyze_config_partitions(&flash_image);

    carve_partitions(&flash_image, carve_dir);

    Some(flash_image)
}

fn write_flash(chip: &str, programmer: &str, file: &str) {
    println!(
        "Writing flash with chip: {}, programmer: {}, file: {}",
        chip, programmer, file
    );
    ProcessCommand::new("flashrom")
        .args(&["-p", programmer, "-c", chip, "-w", file])
        .status()
        .expect("Failed to execute flashrom");
}

fn pad16(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let pad = 16 - (out.len() % 16);
    if pad != 16 {
        out.extend(std::iter::repeat(pad as u8).take(pad));
    }
    out
}

fn decrypt_config(file: &str, output: &str, logger: &ProgressLogger) -> Result<()> {
    let data = fs::read(file)?;
    type IVType = GenericArray<u8, aes::cipher::typenum::U16>;
    let key = GenericArray::from([
        0x2E, 0xB3, 0x8F, 0x7E, 0xC4, 0x1D, 0x4B, 0x8E, 0x14, 0x22, 0x80, 0x5B, 0xCD, 0x5F, 0x74,
        0x0B, 0xC3, 0xB9, 0x5B, 0xE1, 0x63, 0xE3, 0x9D, 0x67, 0x57, 0x9E, 0xB3, 0x44, 0x42, 0x7F,
        0x78, 0x36,
    ]);
    let iv: IVType = GenericArray::from([
        0x36, 0x00, 0x28, 0xC9, 0x06, 0x42, 0x42, 0xF8, 0x10, 0x74, 0xF4, 0xC1, 0x27, 0xD2, 0x99,
        0xF6,
    ]);

    let cipher = aes::Aes256::new(&key);
    let cbc_decrypt = |cipher: &aes::Aes256, data: &[u8], iv: &IVType| -> Vec<u8> {
        let data = pad16(data);
        let mut decrypted = vec![0u8; data.len()];
        let mut prev = iv.clone();
        for (i, chunk) in data.chunks(16).enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            for j in 0..16 {
                decrypted[i * 16 + j] = block[j] ^ prev[j];
            }
            prev = GenericArray::clone_from_slice(chunk);
        }
        decrypted
    };
    let decrypted_stage1 = cbc_decrypt(&cipher, &data, &iv);
    let mut decompressed_stage1 = Vec::new();
    ZlibDecoder::new(&decrypted_stage1[..]).read_to_end(&mut decompressed_stage1)?;

    let md5_bytes = &decompressed_stage1[..16];
    let stage2_data = &decompressed_stage1[16..];

    let expected_md5 = md5::compute(b"RE300");
    let expected_md5_bytes = expected_md5.0;
    if md5_bytes == expected_md5_bytes {
        logger.info("MD5 hash verification: PASSED (matches RE300)");
    } else {
        logger.warn(&format!(
            "MD5 hash verification: FAILED\nExpected: {:02x?}\nExtracted: {:02x?}",
            expected_md5_bytes, md5_bytes
        ));
    }

    let decrypted_stage2 = cbc_decrypt(&cipher, stage2_data, &iv);
    let mut decompressed_stage2: Vec<u8> = Vec::new();
    ZlibDecoder::new(&decrypted_stage2[..]).read_to_end(&mut decompressed_stage2)?;

    fs::write(output, &decompressed_stage2)?;
    logger.info(&format!("Decrypted config written to: {}", output));
    Ok(())
}

fn encrypt_config(file: &str, output: &str, logger: &ProgressLogger) -> Result<()> {
    let data = fs::read(file)?;
    type IVType = GenericArray<u8, aes::cipher::typenum::U16>;
    let key = GenericArray::from([
        0x2E, 0xB3, 0x8F, 0x7E, 0xC4, 0x1D, 0x4B, 0x8E, 0x14, 0x22, 0x80, 0x5B, 0xCD, 0x5F, 0x74,
        0x0B, 0xC3, 0xB9, 0x5B, 0xE1, 0x63, 0xE3, 0x9D, 0x67, 0x57, 0x9E, 0xB3, 0x44, 0x42, 0x7F,
        0x78, 0x36,
    ]);
    let iv: IVType = GenericArray::from([
        0x36, 0x00, 0x28, 0xC9, 0x06, 0x42, 0x42, 0xF8, 0x10, 0x74, 0xF4, 0xC1, 0x27, 0xD2, 0x99,
        0xF6,
    ]);
    let mut encoder2 = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder2.write_all(&data)?;
    let compressed2 = encoder2.finish()?;
    let cbc_encrypt = |cipher: &aes::Aes256, data: &[u8], iv: &IVType| -> Vec<u8> {
        let data = pad16(data);
        let mut encrypted = vec![0u8; data.len()];
        let mut prev = iv.clone();
        for (i, chunk) in data.chunks(16).enumerate() {
            let mut block = GenericArray::clone_from_slice(chunk);
            for j in 0..16 {
                block[j] ^= prev[j];
            }
            cipher.encrypt_block(&mut block);
            encrypted[i * 16..i * 16 + 16].copy_from_slice(&block);
            prev = block.clone();
        }
        encrypted
    };
    let encrypted2 = cbc_encrypt(&aes::Aes256::new(&key), &compressed2, &iv);
    let md5_bytes = md5::compute(b"RE300").0;
    let mut stage1 = Vec::with_capacity(16 + encrypted2.len());
    stage1.extend_from_slice(&md5_bytes);
    stage1.extend_from_slice(&encrypted2);
    let mut encoder1 = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder1.write_all(&stage1)?;
    let compressed1 = encoder1.finish()?;
    let encrypted1 = cbc_encrypt(&aes::Aes256::new(&key), &compressed1, &iv);
    fs::write(output, &encrypted1)?;
    logger.info(&format!("Encrypted config written to: {}", output));
    Ok(())
}

fn create_uimage_with_mkimage(
    kernel_path: &str,
    load_addr: u32,
    entry_addr: u32,
) -> Result<Vec<u8>, FirmwareError> {
    use std::fs;
    use std::process::Command;

    let temp_uimage = "temp_kernel.uimg";

    println!("  Running mkimage to create proper uImage header...");

    // Run mkimage to create uImage
    let output = Command::new("u-boot/tools/mkimage")
        .args(&[
            "-A",
            "mips", // Architecture: MIPS
            "-O",
            "linux", // OS: Linux
            "-T",
            "kernel", // Type: Kernel
            "-C",
            "none", // Compression: None
            "-a",
            &format!("0x{:08x}", load_addr), // Load address
            "-e",
            &format!("0x{:08x}", entry_addr), // Entry point
            "-n",
            "OpenWrt Kernel", // Image name
            "-d",
            kernel_path, // Input data file
            temp_uimage, // Output uImage file
        ])
        .output()
        .map_err(|e| {
            FirmwareError::CommandError(format!(
                "Failed to run mkimage: {}. Make sure u-boot-tools is installed.",
                e
            ))
        })?;

    if !output.status.success() {
        // Clean up temp file if it exists
        let _ = fs::remove_file(temp_uimage);
        return Err(FirmwareError::CommandError(format!(
            "mkimage failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    println!(
        "  mkimage output: {}",
        String::from_utf8_lossy(&output.stdout)
    );

    // Read the created uImage
    let uimage_data = fs::read(temp_uimage).map_err(|e| FirmwareError::IoError(e))?;

    // Clean up temp file
    fs::remove_file(temp_uimage).map_err(|e| FirmwareError::IoError(e))?;

    println!("  Successfully created uImage with mkimage");
    Ok(uimage_data)
}

fn build_flash_with_components(
    uboot_path: &str,
    kernel_path: &str,
    radio_path: Option<&str>,
    config_path: Option<&str>,
    create_uimage: bool,
    _skip_env: bool,
) -> Result<(), FirmwareError> {
    println!("Building flash image with custom components...");
    println!("New partition layout: U-Boot=144KB, Firmware starts at 0x24000, Radio at 0x7F0000");

    // Read U-Boot SPL
    let uboot_data = fs::read(uboot_path).map_err(|e| FirmwareError::IoError(e))?;

    // New U-Boot partition size is 144KB (0x24000)
    const UBOOT_PARTITION_SIZE: usize = 0x24000;
    if uboot_data.len() > UBOOT_PARTITION_SIZE {
        return Err(FirmwareError::ValidationError(format!(
            "U-Boot image too large: {} bytes (max: {} bytes / 144KB)",
            uboot_data.len(),
            UBOOT_PARTITION_SIZE
        )));
    }

    // Read initramfs kernel
    let mut kernel_data = fs::read(kernel_path).map_err(|e| FirmwareError::IoError(e))?;

    // Create uImage header if requested
    if create_uimage {
        println!("Creating uImage header using mkimage...");
        kernel_data = create_uimage_with_mkimage(kernel_path, 0x80000000, 0x80000000)?;
        println!("  uImage created: {} bytes", kernel_data.len());
    }

    // Firmware partition starts at 0x24000 and goes to 0x600000 (config partition start)
    const FIRMWARE_START: usize = 0x24000;
    const CONFIG_START: usize = 0x650000;
    const RADIO_START: usize = 0x7F0000;

    // Calculate available space for firmware (kernel + any additional components)
    let available_firmware_space = CONFIG_START - FIRMWARE_START; // 0x5DC000 = 6000KB
    if kernel_data.len() > available_firmware_space {
        return Err(FirmwareError::ValidationError(format!(
            "Kernel image too large. Available firmware space: 0x{:X} bytes ({}KB), kernel size: 0x{:X} bytes ({}KB)",
            available_firmware_space,
            available_firmware_space / 1024,
            kernel_data.len(),
            kernel_data.len() / 1024
        )));
    }

    println!("Partition layout validation:");
    println!(
        "  U-Boot: 0x000000 - 0x{:06X} ({} bytes, max {}KB)",
        UBOOT_PARTITION_SIZE,
        uboot_data.len(),
        UBOOT_PARTITION_SIZE / 1024
    );
    println!(
        "  Firmware: 0x{:06X} - 0x{:06X} ({} bytes available, {}KB)",
        FIRMWARE_START,
        CONFIG_START,
        available_firmware_space,
        available_firmware_space / 1024
    );
    println!(
        "  Kernel size: {} bytes ({}KB)",
        kernel_data.len(),
        kernel_data.len() / 1024
    );

    // Read or extract radio partition
    let radio_data = if let Some(radio_path) = radio_path {
        fs::read(radio_path).map_err(|e| FirmwareError::IoError(e))?
    } else {
        // Extract from original flash dump
        let mut flash_dump =
            fs::File::open("flash_dump.bin").map_err(|e| FirmwareError::IoError(e))?;
        flash_dump
            .seek(io::SeekFrom::Start(RADIO_START as u64))
            .map_err(|e| FirmwareError::IoError(e))?;
        let mut radio = vec![0u8; 0x10000];
        flash_dump
            .read_exact(&mut radio)
            .map_err(|e| FirmwareError::IoError(e))?;
        radio
    };

    if radio_data.len() > 0x10000 {
        return Err(FirmwareError::ValidationError(
            "Radio data too large (max 64KB)".to_string(),
        ));
    }

    // Read or extract config partition
    const CONFIG_SIZE: usize = 0x50000; // 320KB
    let config_data = if let Some(config_path) = config_path {
        let data = fs::read(config_path).map_err(|e| FirmwareError::IoError(e))?;
        if data.len() > CONFIG_SIZE {
            return Err(FirmwareError::ValidationError(format!(
                "Config data too large: {} bytes (max: {} bytes)",
                data.len(),
                CONFIG_SIZE
            )));
        }
        data
    } else {
        // Extract from original flash dump
        match fs::File::open("flash_dump.bin") {
            Ok(mut flash_dump) => {
                flash_dump
                    .seek(io::SeekFrom::Start(CONFIG_START as u64))
                    .map_err(|e| FirmwareError::IoError(e))?;
                let mut config = vec![0u8; CONFIG_SIZE];
                flash_dump
                    .read_exact(&mut config)
                    .map_err(|e| FirmwareError::IoError(e))?;
                println!("  Extracted config partition from flash_dump.bin");
                config
            }
            Err(_) => {
                // If no flash dump available, create empty config (will be filled with 0xFF)
                println!("  No flash_dump.bin found, using empty config partition");
                vec![0xFFu8; CONFIG_SIZE]
            }
        }
    };

    // Create new 8MB flash image
    let mut new_flash = vec![0xFFu8; 0x800000]; // 8MB filled with 0xFF

    println!("Building flash image...");

    // Copy U-Boot to partition (0x0 - 0x24000)
    new_flash[..uboot_data.len()].copy_from_slice(&uboot_data);
    println!("  Placed U-Boot: {} bytes at 0x000000", uboot_data.len());

    // Place kernel in firmware partition starting at 0x24000
    let kernel_start = FIRMWARE_START;
    new_flash[kernel_start..kernel_start + kernel_data.len()].copy_from_slice(&kernel_data);
    println!(
        "  Placed kernel: {} bytes at 0x{:06X}",
        kernel_data.len(),
        kernel_start
    );

    // Place config partition at 0x600000
    new_flash[CONFIG_START..CONFIG_START + config_data.len()].copy_from_slice(&config_data);
    println!(
        "  Placed config: {} bytes at 0x{:06X}",
        config_data.len(),
        CONFIG_START
    );

    // Copy radio partition at 0x7F0000
    new_flash[RADIO_START..RADIO_START + radio_data.len()].copy_from_slice(&radio_data);
    println!(
        "  Placed radio: {} bytes at 0x{:06X}",
        radio_data.len(),
        RADIO_START
    );

    // Write to file
    let output_name = "complete_flash_image.bin";
    println!("Writing output file...");
    fs::write(output_name, &new_flash).map_err(|e| FirmwareError::IoError(e))?;
    println!("Output file written");

    println!("Complete flash image created: {}", output_name);
    println!("Final layout:");
    println!(
        "  0x000000 - 0x{:06X}: U-Boot partition ({} bytes)",
        UBOOT_PARTITION_SIZE,
        uboot_data.len()
    );
    println!(
        "  0x{:06X} - 0x{:06X}: Firmware partition",
        FIRMWARE_START, CONFIG_START
    );
    println!(
        "    └─ 0x{:06X} - 0x{:06X}: Kernel ({} bytes)",
        kernel_start,
        kernel_start + kernel_data.len(),
        kernel_data.len()
    );
    println!(
        "  0x{:06X} - 0x650000: Config partition ({} bytes)",
        CONFIG_START,
        config_data.len()
    );
    println!("  0x650000 - 0x{:06X}: Unused space", RADIO_START);
    println!(
        "  0x{:06X} - 0x800000: Radio partition ({} bytes)",
        RADIO_START,
        radio_data.len()
    );

    Ok(())
}

fn build_flash_with_separate_components(
    uboot_path: &str,
    kernel_path: &str,
    rootfs_path: &str,
    radio_path: Option<&str>,
    create_uimage: bool,
    logger: &ProgressLogger,
) -> Result<(), FirmwareError> {
    logger.info("Building flash image with separate kernel and rootfs components...");
    logger.info("Layout: U-Boot=196KB, U-Boot-env=64KB, Kernel=3MB, Rootfs=~4.7MB, Radio=64KB");

    // Read U-Boot SPL
    let uboot_data = fs::read(uboot_path).map_err(|e| FirmwareError::IoError(e))?;

    // U-Boot partition: 0x0 - 0x30000 (196KB)
    // U-Boot env: 0x30000 - 0x40000 (64KB)
    const UBOOT_SIZE: usize = 0x30000;
    if uboot_data.len() > UBOOT_SIZE {
        return Err(FirmwareError::ValidationError(format!(
            "U-Boot image too large: {} bytes (max: {} bytes / 144KB)",
            uboot_data.len(),
            UBOOT_SIZE
        )));
    }

    // Read kernel
    let mut kernel_data = fs::read(kernel_path).map_err(|e| FirmwareError::IoError(e))?;

    // Create uImage header if requested
    if create_uimage {
        logger.info("Creating uImage header using mkimage...");
        kernel_data = create_uimage_with_mkimage(kernel_path, 0x80000000, 0x80000000)?;
        logger.info(&format!("uImage created: {} bytes", kernel_data.len()));
    }

    // Read rootfs
    let rootfs_data = fs::read(rootfs_path).map_err(|e| FirmwareError::IoError(e))?;

    // Partition layout based on updated device tree:
    // Kernel: 0x40000 - 0x2E0000 (2.6MB)
    // Rootfs: 0x2E0000 - 0x7F0000 (~5.1MB)
    // Radio: 0x7F0000 - 0x800000 (64KB)
    const KERNEL_START: usize = 0x40000;
    const KERNEL_SIZE: usize = 0x2A0000; // 2.6MB
    const ROOTFS_START: usize = 0x2E0000;
    const ROOTFS_SIZE: usize = 0x510000; // ~5.3MB
    const RADIO_START: usize = 0x7F0000;
    const RADIO_SIZE: usize = 0x10000; // 64KB

    // Validate sizes
    if kernel_data.len() > KERNEL_SIZE {
        return Err(FirmwareError::ValidationError(format!(
            "Kernel too large: {} bytes (max: {} bytes / 3MB)",
            kernel_data.len(),
            KERNEL_SIZE
        )));
    }

    if rootfs_data.len() > ROOTFS_SIZE {
        return Err(FirmwareError::ValidationError(format!(
            "Rootfs too large: {} bytes (max: {} bytes / ~4.8MB)",
            rootfs_data.len(),
            ROOTFS_SIZE
        )));
    }

    // Read radio partition
    let radio_data = if let Some(radio_path) = radio_path {
        fs::read(radio_path).map_err(|e| FirmwareError::IoError(e))?
    } else {
        // Extract from original flash dump
        match fs::File::open("flash_dump.bin") {
            Ok(mut flash_dump) => {
                flash_dump
                    .seek(io::SeekFrom::Start(RADIO_START as u64))
                    .map_err(|e| FirmwareError::IoError(e))?;
                let mut radio = vec![0u8; RADIO_SIZE];
                flash_dump
                    .read_exact(&mut radio)
                    .map_err(|e| FirmwareError::IoError(e))?;
                logger.info("Extracted radio partition from flash_dump.bin");
                radio
            }
            Err(_) => {
                logger.warn("No flash_dump.bin found, using empty radio partition");
                vec![0xFFu8; RADIO_SIZE]
            }
        }
    };

    if radio_data.len() > RADIO_SIZE {
        return Err(FirmwareError::ValidationError(format!(
            "Radio data too large: {} bytes (max: {} bytes / 64KB)",
            radio_data.len(),
            RADIO_SIZE
        )));
    }

    logger.info("Partition layout validation:");
    logger.info(&format!(
        "  U-Boot: 0x000000 - 0x{:06X} ({} bytes, max {}KB)",
        UBOOT_SIZE,
        uboot_data.len(),
        UBOOT_SIZE / 1024
    ));
    logger.info(&format!(
        "  Kernel: 0x{:06X} - 0x{:06X} ({} bytes, max {}KB)",
        KERNEL_START,
        KERNEL_START + KERNEL_SIZE,
        kernel_data.len(),
        KERNEL_SIZE / 1024
    ));
    logger.info(&format!(
        "  Rootfs: 0x{:06X} - 0x{:06X} ({} bytes, max {}KB)",
        ROOTFS_START,
        ROOTFS_START + ROOTFS_SIZE,
        rootfs_data.len(),
        ROOTFS_SIZE / 1024
    ));
    logger.info(&format!(
        "  Radio:  0x{:06X} - 0x{:06X} ({} bytes, max {}KB)",
        RADIO_START,
        RADIO_START + RADIO_SIZE,
        radio_data.len(),
        RADIO_SIZE / 1024
    ));

    // Create new 8MB flash image
    let mut new_flash = vec![0xFFu8; 0x800000]; // 8MB filled with 0xFF

    logger.info("Building flash image...");

    // Place U-Boot (0x0 - 0x30000)
    new_flash[..uboot_data.len()].copy_from_slice(&uboot_data);
    logger.info(&format!(
        "Placed U-Boot: {} bytes at 0x000000",
        uboot_data.len()
    ));

    // Place kernel (0x40000 - 0x340000)
    new_flash[KERNEL_START..KERNEL_START + kernel_data.len()].copy_from_slice(&kernel_data);
    logger.info(&format!(
        "Placed kernel: {} bytes at 0x{:06X}",
        kernel_data.len(),
        KERNEL_START
    ));

    // Place rootfs (0x340000 - 0x7F0000)
    new_flash[ROOTFS_START..ROOTFS_START + rootfs_data.len()].copy_from_slice(&rootfs_data);
    logger.info(&format!(
        "Placed rootfs: {} bytes at 0x{:06X}",
        rootfs_data.len(),
        ROOTFS_START
    ));

    // Place radio (0x7F0000 - 0x800000)
    new_flash[RADIO_START..RADIO_START + radio_data.len()].copy_from_slice(&radio_data);
    logger.info(&format!(
        "Placed radio: {} bytes at 0x{:06X}",
        radio_data.len(),
        RADIO_START
    ));

    // Write to file
    let output_name = "complete_flash_separate.bin";
    logger.info("Writing output file...");
    fs::write(output_name, &new_flash).map_err(|e| FirmwareError::IoError(e))?;
    logger.info("Output file written");

    logger.info(&format!("Complete flash image created: {}", output_name));
    logger.info("Final layout:");
    logger.info(&format!(
        "  0x000000 - 0x{:06X}: U-Boot partition ({} bytes)",
        UBOOT_SIZE,
        uboot_data.len()
    ));
    logger.info(&format!(
        "  0x{:06X} - 0x{:06X}: Kernel partition ({} bytes)",
        KERNEL_START,
        KERNEL_START + KERNEL_SIZE,
        kernel_data.len()
    ));
    logger.info(&format!(
        "  0x{:06X} - 0x{:06X}: Rootfs partition ({} bytes)",
        ROOTFS_START,
        ROOTFS_START + ROOTFS_SIZE,
        rootfs_data.len()
    ));
    logger.info(&format!(
        "  0x{:06X} - 0x{:06X}: Radio partition ({} bytes)",
        RADIO_START,
        RADIO_START + RADIO_SIZE,
        radio_data.len()
    ));
    logger.info(
        "This image uses separate kernel and rootfs partitions as defined in the device tree.",
    );

    Ok(())
}
