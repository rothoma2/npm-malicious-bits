#!/usr/bin/env python3
"""
NPM Malicious IOCs CLI Tool

A command-line tool for collecting and managing NPM malicious Indicators
of Compromise (IOCs).
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pprint import pprint
from pathlib import Path
from typing import Optional
from .models import AffectedPackage, MaliciousPackageReport
from .aikido_client import AikidoClient


def parse_malicious_json_files(folder_path: str) -> MaliciousPackageReport:
    """
    Traverse a folder and parse all JSON files to extract affected package
    ecosystem information.

    Args:
        folder_path: Path to the folder to traverse

    Returns:
        MaliciousPackageReport containing all found packages and statistics
    """
    debugFlag = False

    folder_path_obj = Path(folder_path)

    if not folder_path_obj.exists():
        raise FileNotFoundError(f"Folder not found: {folder_path}")

    if not folder_path_obj.is_dir():
        raise ValueError(f"Path is not a directory: {folder_path}")

    # Detect reporter based on folder path
    reporter = "unknown"
    if "AIKIDO" in folder_path or "aikido" in folder_path.lower():
        reporter = "Aikido Security"
    elif "ossf" in folder_path.lower():
        reporter = "OpenSSF"

    packages = []
    files_processed = 0

    print(f"Scanning {folder_path} for JSON files...")

    for json_file in folder_path_obj.rglob("MAL*.json"):

        files_processed += 1
        try:
            
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if debugFlag:
                pprint(data)
                debugFlag = False


            published = data.get('published')
            affected = data.get('affected', [])
            versions = data.get('versions', [])

            for affected_item in affected:
                
                package_info = affected_item.get('package', {})
                ecosystem = package_info.get('ecosystem')
                
                if ecosystem:
                    package = AffectedPackage(
                        ecosystem=ecosystem,
                        published=published,
                        package_name=package_info.get('name'),
                        versions=versions,
                        reporter=reporter
                    )
                    packages.append(package)

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            print(f"Warning: Could not parse {json_file}: {e}")
            continue
 
        except Exception as e:
            print(f"Error processing {json_file}: {e}")
            continue

    report = MaliciousPackageReport(
        packages=packages,
        total_files_processed=files_processed,
        total_packages_found=len(packages)
    )

    print(f"Processing complete: {files_processed} files processed, "
          f"{len(packages)} packages found")

    print(f"Ecosystems found: {', '.join(report.get_ecosystems())}")

    return report


def parse_recent_malicious_json_files(
    folder_path: Optional[str] = None,
    hours: int = 72
) -> MaliciousPackageReport:
    """
    Parse JSON files filtering for those published within the specified hours.
    If no folder_path is provided, searches for OSSF and Aikido folders
    in /tmp/npm_malicious_bits/.
    
    Args:
        folder_path: Path to the folder to traverse (optional)
        hours: Number of hours to look back (default: 72)
    
    Returns:
        MaliciousPackageReport containing only recent packages
    """
    all_packages = []
    total_files = 0
    
    if folder_path:
        # Use provided folder path
        folders_to_scan = [folder_path]
    else:
        # Auto-discover folders in /tmp/npm_malicious_bits/
        base_dir = Path("/tmp/npm_malicious_bits")
        folders_to_scan = []
        
        if base_dir.exists():
            print(f"Searching for data in {base_dir}...")
            # Find OSSF folders
            ossf_folders = list(base_dir.glob("ossf_malicious_packages_*"))
            if ossf_folders:
                # Use the most recent OSSF folder
                ossf_folder = max(
                    ossf_folders,
                    key=lambda p: p.stat().st_mtime
                )
                ossf_malicious = ossf_folder / "osv" / "malicious"
                if ossf_malicious.exists():
                    folders_to_scan.append(str(ossf_malicious))
                    print(f"Found OSSF data: {ossf_folder.name}")
            
            # Find Aikido folders
            aikido_folders = list(base_dir.glob("AIKIDO_*"))
            if aikido_folders:
                # Use the most recent Aikido folder
                aikido_folder = max(
                    aikido_folders,
                    key=lambda p: p.stat().st_mtime
                )
                folders_to_scan.append(str(aikido_folder))
                print(f"Found Aikido data: {aikido_folder.name}")
        
        if not folders_to_scan:
            print("No OSSF or Aikido folders found in "
                  "/tmp/npm_malicious_bits/")
            print("Run 'npm-iocs collect' first to fetch data.")
            return MaliciousPackageReport(
                packages=[],
                total_files_processed=0,
                total_packages_found=0
            )
    
    # Parse all discovered folders
    for folder in folders_to_scan:
        report = parse_malicious_json_files(folder)
        all_packages.extend(report.packages)
        total_files += report.total_files_processed
    
    # Combine all packages into one report
    combined_report = MaliciousPackageReport(
        packages=all_packages,
        total_files_processed=total_files,
        total_packages_found=len(all_packages)
    )
    
    # Filter for recent packages
    recent_packages = combined_report.get_packages_within_hours(hours)
    
    filtered_report = MaliciousPackageReport(
        packages=recent_packages,
        total_files_processed=total_files,
        total_packages_found=len(recent_packages)
    )
    
    # Deduplicate packages and track reporters
    package_map = {}  # key: (ecosystem, package_name), value: {reporters, pkg}
    
    for pkg in recent_packages:
        key = (pkg.ecosystem, pkg.package_name)
        if key in package_map:
            # Package found by multiple reporters
            package_map[key]['reporters'].add(pkg.reporter)
            # Merge versions if different
            if pkg.versions:
                existing_versions = set(package_map[key]['pkg'].versions or [])
                new_versions = set(pkg.versions)
                merged_versions = list(existing_versions | new_versions)
                package_map[key]['pkg'].versions = merged_versions
        else:
            package_map[key] = {
                'reporters': {pkg.reporter},
                'pkg': pkg
            }
    
    # Separate packages by reporter status
    both_reporters = []
    openssf_only = []
    aikido_only = []
    
    for key, data in package_map.items():
        reporters = data['reporters']
        pkg = data['pkg']
        
        if len(reporters) > 1:
            # Found by both
            both_reporters.append((pkg, sorted(reporters)))
        elif 'OpenSSF' in reporters:
            openssf_only.append(pkg)
        elif 'Aikido Security' in reporters:
            aikido_only.append(pkg)
        else:
            # Unknown reporter, add to both section
            both_reporters.append((pkg, sorted(reporters)))
    
    # Display table of recent packages
    print(f"\n{'='*100}")
    print(f"Recent Packages (last {hours} hours): "
          f"{len(package_map)} unique packages found")
    print(f"{'='*100}")
    
    # Section 1: Packages found by both reporters
    if both_reporters:
        print(f"\n{'='*100}")
        print(f"Found by Multiple Reporters ({len(both_reporters)} packages)")
        print(f"{'='*100}")
        print(f"{'Ecosystem':<12} {'Package Name':<35} "
              f"{'Versions':<32} {'Reporters':<20}")
        print(f"{'-'*12} {'-'*35} {'-'*32} {'-'*20}")
        
        for pkg, reporters in sorted(both_reporters,
                                     key=lambda x: (x[0].ecosystem,
                                                    x[0].package_name)):
            ecosystem = pkg.ecosystem[:12]
            package_name = pkg.package_name[:35] if pkg.package_name else "N/A"
            
            # Format versions (max 32 chars)
            if pkg.versions:
                versions_str = ", ".join(pkg.versions)
                if len(versions_str) > 32:
                    versions_str = versions_str[:29] + "..."
            else:
                versions_str = "N/A"
            
            reporters_str = " + ".join([r.split()[0] for r in reporters])
            reporters_str = reporters_str[:20]
            
            print(f"{ecosystem:<12} {package_name:<35} "
                  f"{versions_str:<32} {reporters_str:<20}")
    
    # Section 2: Packages found only by OpenSSF
    if openssf_only:
        print(f"\n{'='*100}")
        print(f"Found Exclusively by OpenSSF ({len(openssf_only)} packages)")
        print(f"{'='*100}")
        print(f"{'Ecosystem':<12} {'Package Name':<35} "
              f"{'Versions':<32} {'Reporter':<20}")
        print(f"{'-'*12} {'-'*35} {'-'*32} {'-'*20}")
        
        for pkg in sorted(openssf_only,
                         key=lambda x: (x.ecosystem, x.package_name)):
            ecosystem = pkg.ecosystem[:12]
            package_name = pkg.package_name[:35] if pkg.package_name else "N/A"
            
            # Format versions (max 32 chars)
            if pkg.versions:
                versions_str = ", ".join(pkg.versions)
                if len(versions_str) > 32:
                    versions_str = versions_str[:29] + "..."
            else:
                versions_str = "N/A"
            
            print(f"{ecosystem:<12} {package_name:<35} "
                  f"{versions_str:<32} {'OpenSSF':<20}")
    
    # Section 3: Packages found only by Aikido
    if aikido_only:
        print(f"\n{'='*100}")
        print(f"Found Exclusively by Aikido ({len(aikido_only)} packages)")
        print(f"{'='*100}")
        print(f"{'Ecosystem':<12} {'Package Name':<35} "
              f"{'Versions':<32} {'Reporter':<20}")
        print(f"{'-'*12} {'-'*35} {'-'*32} {'-'*20}")
        
        for pkg in sorted(aikido_only,
                         key=lambda x: (x.ecosystem, x.package_name)):
            ecosystem = pkg.ecosystem[:12]
            package_name = pkg.package_name[:35] if pkg.package_name else "N/A"
            
            # Format versions (max 32 chars)
            if pkg.versions:
                versions_str = ", ".join(pkg.versions)
                if len(versions_str) > 32:
                    versions_str = versions_str[:29] + "..."
            else:
                versions_str = "N/A"
            
            print(f"{ecosystem:<12} {package_name:<35} "
                  f"{versions_str:<32} {'Aikido Security':<20}")
    
    if recent_packages:
        print(f"\n{'='*100}")
        
        # Show summary statistics
        print("\nSummary Statistics:")
        print(f"  Total unique packages: {len(package_map)}")
        print(f"  Found by both reporters: {len(both_reporters)}")
        print(f"  Found only by OpenSSF: {len(openssf_only)}")
        print(f"  Found only by Aikido: {len(aikido_only)}")
        
        # Show ecosystem breakdown
        ecosystem_counts = {}
        for pkg in recent_packages:
            ecosystem_counts[pkg.ecosystem] = (
                ecosystem_counts.get(pkg.ecosystem, 0) + 1
            )
        
        print("\nEcosystem Breakdown:")
        for ecosystem, count in sorted(ecosystem_counts.items()):
            print(f"  {ecosystem}: {count} packages")
    else:
        print(f"No packages found within the last {hours} hours")
    
    return filtered_report


def collect_iocs(output: Optional[str] = None) -> None:
    """
    Collect malicious IOCs from multiple sources: OSSF and Aikido.

    Args:
        output: The output file to save IOCs to
    """
    print("Collecting malicious IOCs from multiple sources...")
    print("=" * 60)

    all_packages = []
    total_files = 0
    source_stats = {}

    # Source 1: Clone OSSF malicious packages repository
    print("\n[1/2] Fetching OSSF malicious packages repository...")
    temp_dir = clone_ossf_malicious_packages()
    if temp_dir:
        malicious_path = os.path.join(temp_dir, "osv", "malicious")
        if os.path.exists(malicious_path):
            ossf_report = parse_malicious_json_files(malicious_path)
            all_packages.extend(ossf_report.packages)
            total_files += ossf_report.total_files_processed
            source_stats['OSSF'] = {
                'files': ossf_report.total_files_processed,
                'packages': len(ossf_report.packages),
                'ecosystems': ossf_report.get_ecosystems()
            }
            print(f"OSSF: {len(ossf_report.packages)} packages from "
                  f"{ossf_report.total_files_processed} files")
        else:
            print("Warning: Could not find OSSF malicious packages folder")
            source_stats['OSSF'] = {'files': 0, 'packages': 0, 'ecosystems': []}
    else:
        print("Warning: Failed to clone OSSF repository")
        source_stats['OSSF'] = {
            'files': 0,
            'packages': 0,
            'ecosystems': []
        }

    # Source 2: Fetch from Aikido API
    print("\n[2/2] Fetching latest packages from Aikido Security...")
    aikido_client = AikidoClient()
    try:
        # Fetch for npm ecosystem with high limit
        aikido_predictions = aikido_client.list_latest_malware_predictions(
            ecosystem="npm",
            per_page=10000
        )
        
        if aikido_predictions:
            # Export to OpenSSF format files
            aikido_dir = aikido_client.export_to_openssf_format(
                aikido_predictions
            )
            
            # Parse the exported files to get AffectedPackage objects
            aikido_report = parse_malicious_json_files(aikido_dir)
            all_packages.extend(aikido_report.packages)
            total_files += aikido_report.total_files_processed
            source_stats['Aikido'] = {
                'files': aikido_report.total_files_processed,
                'packages': len(aikido_report.packages),
                'ecosystems': aikido_report.get_ecosystems()
            }
            print(f"Aikido: {len(aikido_report.packages)} packages from "
                  f"{aikido_report.total_files_processed} files")
        else:
            print("Warning: No predictions found from Aikido")
            source_stats['Aikido'] = {
                'files': 0,
                'packages': 0,
                'ecosystems': []
            }
    except Exception as e:
        print(f"Error fetching from Aikido: {e}")
        source_stats['Aikido'] = {'files': 0, 'packages': 0, 'ecosystems': []}
    finally:
        aikido_client.close()

    # Create combined report
    combined_report = MaliciousPackageReport(
        packages=all_packages,
        total_files_processed=total_files,
        total_packages_found=len(all_packages)
    )

    # Display summary statistics
    print("\n" + "=" * 60)
    print("Collection Summary:")
    print("=" * 60)
    print(f"Total files processed: {total_files}")
    print(f"Total packages found: {len(all_packages)}")
    print("\nBy Source:")
    for source, stats in source_stats.items():
        print(f"  {source}: {stats['packages']} packages "
              f"from {stats['files']} files")
        if stats['ecosystems']:
            print(f"    Ecosystems: {', '.join(stats['ecosystems'])}")
    
    print(f"\nCombined ecosystems: "
          f"{', '.join(combined_report.get_ecosystems())}")
    print("Ecosystem statistics:")
    for ecosystem, count in combined_report.get_ecosystem_statistics().items():
        print(f"  {ecosystem}: {count} packages")

    # Save to output file if specified
    if output and combined_report:
        print(f"\nSaving combined IOCs to: {output}")
        output_data = {
            'sources': source_stats,
            'combined_report': json.loads(combined_report.to_json())
        }
        with open(output, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)
        print(f"Results saved to {output}")
    elif combined_report and len(all_packages) > 0:
        print("\nIOCs collected successfully (no output file specified)")
    else:
        print("\nNo IOCs collected")


def clone_ossf_malicious_packages(local_path: Optional[str] = None) -> Optional[str]:  # noqa: E501
    """
    Clone the OSSF malicious packages repository and return the local path.
    
    Args:
        local_path: Path where to clone the repository. If None, uses temp dir.
        
    Returns:
        Local path to the cloned repository, or None if cloning failed
    """

    ossf_repo_url = "https://github.com/ossf/malicious-packages"

    if local_path is None:
        base_dir = "/tmp/npm_malicious_bits"
        os.makedirs(base_dir, exist_ok=True)
        local_path = tempfile.mkdtemp(
            prefix="ossf_malicious_packages_",
            dir=base_dir
        )
        print(f"Cloning to temporary directory: {local_path}")
    else:
        print(f"Cloning to: {local_path}")

    try:
        print(f"Cloning {ossf_repo_url}...")
        subprocess.run(
            ["git", "clone", ossf_repo_url, local_path],
            capture_output=True,
            text=True,
            check=True
        )
        print("Repository cloned successfully!")
        
        # Count JSON files in /osv/malicious/ folder
        malicious_path = os.path.join(local_path, "osv", "malicious")
        json_count = 0
        
        if os.path.exists(malicious_path):

            print(f"Scanning {malicious_path} for JSON files...")
            for root, dirs, files in os.walk(malicious_path):
                for file_name in files:
                    if file_name.lower().endswith('.json'):

                        json_count += 1
            
            print(f"Found {json_count} JSON files in /osv/malicious/ folder")
        else:
            print("Warning: /osv/malicious/ folder not found in repository")
        
        return local_path
        
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        print(f"Command output: {e.stderr}")
        return None
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None


def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog='npm-iocs',
        description='NPM Malicious IOCs CLI Tool - Collect and manage '
                    'NPM malicious indicators',
        epilog='For more information, visit: '
               'https://github.com/rothoma2/npm-malicious-bits'
    )

    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.1.0'
    )

    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='COMMAND'
    )

    # Collect command
    collect_parser = subparsers.add_parser(
        'collect',
        help='Collect malicious IOCs from OSSF repository'
    )
    collect_parser.add_argument(
        '--output', '-o',
        help='Output file to save collected IOCs'
    )
    collect_parser.add_argument(
        '--format',
        choices=['json', 'csv', 'txt'],
        default='json',
        help='Output format (default: json)'
    )

    # Recent command - Parse JSON files filtering for packages
    # published in last 72h
    recent_parser = subparsers.add_parser(
        'recent',
        help='Parse JSON files filtering for packages published in last 72h'
    )
    recent_parser.add_argument(
        'folder_path',
        nargs='?',
        default=None,
        help='Path to folder containing JSON files (optional, '
             'auto-discovers if not provided)'
    )
    recent_parser.add_argument(
        '--hours',
        type=int,
        default=72,
        help='Lookback window in hours (default: 72)'
    )
    recent_parser.add_argument(
        '--output', '-o',
        help='Output file to save the filtered results (JSON format)'
    )

    # Clone OSSF malicious packages command
    clone_parser = subparsers.add_parser(
        'clone-ossf',
        help='Clone OSSF malicious packages repository and count JSON files'
    )
    clone_parser.add_argument(
        '--path',
        help='Local path to clone the repository (default: temp directory)'
    )
    
    # Parse malicious JSON files command
    parse_parser = subparsers.add_parser(
        'parse',
        help='Parse JSON files in a folder to extract affected packages'
    )
    parse_parser.add_argument(
        'folder_path',
        help='Path to folder containing JSON files to parse'
    )
    parse_parser.add_argument(
        '--output', '-o',
        help='Output file to save the parsed results (JSON format)'
    )
    
    return parser


def main() -> int:
    """Main entry point for the CLI tool."""
    parser = create_parser()
    args = parser.parse_args()
    
    try:
        if args.command == 'collect':
            collect_iocs(output=args.output)
        elif args.command == 'recent':
            # Handle recent command - parse with time filtering
            folder_path = getattr(args, 'folder_path', None)
            report = parse_recent_malicious_json_files(
                folder_path=folder_path,
                hours=args.hours
            )
            
            if args.output:
                filtered_data = {
                    'filter_applied': f'{args.hours}_hours',
                    'total_files_processed': report.total_files_processed,
                    'total_packages_found': report.total_packages_found,
                    'recent_packages': [
                        pkg.to_dict() for pkg in report.packages
                    ],
                    'ecosystems': report.get_ecosystems()
                }
                with open(args.output, 'w', encoding='utf-8') as f:
                    json.dump(filtered_data, f, indent=2)
                print(f"Filtered results saved to {args.output}")
            else:
                if report.packages:
                    ecosystems = report.get_ecosystems()
                    print(f"Recent ecosystems: {', '.join(ecosystems)}")
                else:
                    print(f"No packages found within the last "
                          f"{args.hours} hours")
                    
        elif args.command == 'clone-ossf':
            clone_ossf_malicious_packages(local_path=args.path)
        elif args.command == 'parse':
            # Standard parsing without time filter
            report = parse_malicious_json_files(args.folder_path)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report.to_json())
                print(f"Results saved to {args.output}")
            else:
                print(report.to_json())
        else:
            parser.print_help()
            return 1

        return 0

    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        return 130
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())