"""
Aikido API Client for fetching malware predictions.

This module provides functionality to fetch and parse malware predictions
from the Aikido Intelligence API.
"""

import requests
import json
import tempfile
import os
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from datetime import datetime
from pathlib import Path


@dataclass
class MalwarePrediction:
    """Represents a malware prediction from Aikido."""

    id: int
    ecosystem: str
    package_name: str
    version: str
    status: str
    release_date: int
    detected_on: int
    last_updated: int
    reason_count: int

    @classmethod
    def from_dict(cls, data: dict) -> "MalwarePrediction":
        """Create a MalwarePrediction from a dictionary."""
        return cls(
            id=data.get("id"),
            ecosystem=data.get("ecosystem"),
            package_name=data.get("package_name"),
            version=data.get("version"),
            status=data.get("status"),
            release_date=data.get("release_date"),
            detected_on=data.get("detected_on"),
            last_updated=data.get("last_updated"),
            reason_count=data.get("reason_count")
        )

    def get_release_datetime(self) -> datetime:
        """Convert release_date timestamp to datetime."""
        return datetime.fromtimestamp(self.release_date)

    def get_detected_datetime(self) -> datetime:
        """Convert detected_on timestamp to datetime."""
        return datetime.fromtimestamp(self.detected_on)

    def get_updated_datetime(self) -> datetime:
        """Convert last_updated timestamp to datetime."""
        return datetime.fromtimestamp(self.last_updated)

    def __str__(self) -> str:
        release_dt = self.get_release_datetime().strftime("%Y-%m-%d %H:%M:%S")
        return (f"{self.ecosystem}/{self.package_name}@{self.version} "
                f"({self.status}) - Released: {release_dt}, "
                f"Reasons: {self.reason_count}")

    def to_openssf_format(self) -> Dict[str, Any]:
        """
        Convert the Aikido prediction to OpenSSF malicious package format.

        Returns:
            Dictionary in OpenSSF format
        """
        # Convert Unix timestamp to ISO 8601 format
        published_dt = self.get_release_datetime()
        modified_dt = self.get_updated_datetime()
        published_iso = published_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        modified_iso = modified_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Generate MAL ID based on Aikido ID
        mal_id = f"MAL-AIKIDO-{self.id}"

        openssf_data = {
            "modified": modified_iso,
            "published": published_iso,
            "schema_version": "1.5.0",
            "id": mal_id,
            "summary": (
                f"Malicious code in {self.package_name} "
                f"({self.ecosystem})"
            ),
            "details": (
                "\n---\n"
                "_-= Per source details. Do not edit below this line.=-_\n\n"
                f"## Source: aikido-security\n"
                f"This package was detected as {self.status} by "
                f"Aikido Security. "
                f"Detection triggered {self.reason_count} reason(s).\n"
            ),
            "affected": [
                {
                    "package": {
                        "ecosystem": self.ecosystem,
                        "name": self.package_name
                    },
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {
                                    "introduced": self.version
                                },
                                {
                                    "last_affected": self.version
                                }
                            ]
                        }
                    ],
                    "versions": [self.version]
                }
            ],
            "credits": [
                {
                    "name": "Aikido Security",
                    "type": "FINDER",
                    "contact": [
                        "https://intel.aikido.dev"
                    ]
                }
            ],
            "database_specific": {
                "malicious-packages-origins": [
                    {
                        "import_time": datetime.now().strftime(
                            "%Y-%m-%dT%H:%M:%S.%fZ"
                        ),
                        "modified_time": modified_iso,
                        "ranges": [
                            {
                                "events": [
                                    {
                                        "introduced": self.version
                                    }
                                ],
                                "type": "ECOSYSTEM"
                            }
                        ],
                        "source": "aikido-security",
                        "aikido_id": self.id,
                        "reason_count": self.reason_count
                    }
                ]
            }
        }

        return openssf_data


class AikidoClient:
    """Client for interacting with Aikido Intelligence API."""

    BASE_URL = "https://intel.aikido.dev/api"

    def __init__(self, timeout: int = 30):
        """
        Initialize the Aikido client.

        Args:
            timeout: Request timeout in seconds (default: 30)
        """
        self.timeout = timeout
        self.session = requests.Session()

    def list_latest_malware_predictions(
        self,
        page: int = 0,
        per_page: int = 1000,
        search: str = "",
        sort_by_column: str = "date",
        ecosystem: str = "npm"
    ) -> List[MalwarePrediction]:
        """
        Fetch latest malware predictions from Aikido API.

        Args:
            page: Page number (default: 0)
            per_page: Number of results per page (default: 1000)
            search: Search query string (default: empty)
            sort_by_column: Column to sort by (default: "date")
            ecosystem: Package ecosystem to filter by (default: "npm")

        Returns:
            List of MalwarePrediction objects

        Raises:
            requests.RequestException: If the API request fails
        """
        url = f"{self.BASE_URL}/listLatestMalwarePredictions"
        params = {
            "page": page,
            "per_page": per_page,
            "search": search,
            "sort_by_column": sort_by_column,
            "ecosystem": ecosystem
        }

        try:
            response = self.session.get(
                url,
                params=params,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()

            # Parse the response into MalwarePrediction objects
            predictions = []
            if isinstance(data, list):
                for item in data:
                    prediction = MalwarePrediction.from_dict(item)
                    predictions.append(prediction)
            elif isinstance(data, dict) and "data" in data:
                # Handle paginated response format
                for item in data["data"]:
                    prediction = MalwarePrediction.from_dict(item)
                    predictions.append(prediction)

            return predictions

        except requests.RequestException as e:
            print(f"Error fetching malware predictions: {e}")
            raise

    def get_all_ecosystems(
        self,
        page: int = 0,
        per_page: int = 1000
    ) -> dict:
        """
        Fetch malware predictions for all ecosystems.

        Args:
            page: Page number (default: 0)
            per_page: Number of results per page (default: 1000)

        Returns:
            Dictionary mapping ecosystem names to lists of predictions
        """
        ecosystems = ["npm", "PyPI", "NuGet", "Maven", "Go", "RubyGems"]
        results = {}

        for ecosystem in ecosystems:
            try:
                predictions = self.list_latest_malware_predictions(
                    page=page,
                    per_page=per_page,
                    ecosystem=ecosystem
                )
                results[ecosystem] = predictions
                print(f"Fetched {len(predictions)} predictions "
                      f"for {ecosystem}")
            except Exception as e:
                print(f"Failed to fetch {ecosystem}: {e}")
                results[ecosystem] = []

        return results

    def export_to_openssf_format(
        self,
        predictions: List[MalwarePrediction],
        output_dir: Optional[str] = None
    ) -> str:
        """
        Export predictions to OpenSSF format JSON files.

        Args:
            predictions: List of MalwarePrediction objects to export
            output_dir: Directory to save files (default: temp dir)

        Returns:
            Path to the directory containing exported files
        """
        # Create output directory
        if output_dir is None:
            base_dir = "/tmp/npm_malicious_bits"
            os.makedirs(base_dir, exist_ok=True)
            output_dir = tempfile.mkdtemp(prefix="AIKIDO_", dir=base_dir)
        else:
            os.makedirs(output_dir, exist_ok=True)

        output_path = Path(output_dir)
        print(f"Exporting {len(predictions)} predictions to {output_path}")

        # Group by ecosystem for better organization
        ecosystem_counts = {}

        for prediction in predictions:
            # Convert to OpenSSF format
            openssf_data = prediction.to_openssf_format()

            # Create filename based on MAL ID
            filename = f"{openssf_data['id']}.json"
            filepath = output_path / filename

            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(openssf_data, f, indent=2)

            # Track ecosystem counts
            ecosystem = prediction.ecosystem
            ecosystem_counts[ecosystem] = (
                ecosystem_counts.get(ecosystem, 0) + 1
            )

        print(f"\nExport complete: {len(predictions)} files created")
        print(f"Output directory: {output_path}")
        print("\nEcosystem breakdown:")
        for ecosystem, count in sorted(ecosystem_counts.items()):
            print(f"  {ecosystem}: {count} packages")

        return str(output_path)

    def fetch_and_export_malware(
        self,
        ecosystem: str = "npm",
        per_page: int = 1000,
        output_dir: Optional[str] = None
    ) -> str:
        """
        Fetch malware predictions and export them to OpenSSF format.

        Args:
            ecosystem: Package ecosystem to fetch (default: "npm")
            per_page: Number of results to fetch (default: 1000)
            output_dir: Directory to save files (default: temp dir)

        Returns:
            Path to the directory containing exported files
        """
        print(f"Fetching {ecosystem} malware predictions from Aikido...")
        predictions = self.list_latest_malware_predictions(
            ecosystem=ecosystem,
            per_page=per_page
        )

        print(f"Fetched {len(predictions)} predictions")
        return self.export_to_openssf_format(predictions, output_dir)

    def close(self):
        """Close the HTTP session."""
        self.session.close()


def main():
    """Main function to demonstrate the Aikido client usage."""
    client = AikidoClient()

    try:
        print("Fetching latest npm malware predictions from Aikido...")
        print("=" * 60)

        predictions = client.list_latest_malware_predictions(
            ecosystem="npm",
            per_page=1000
        )

        print(f"\nTotal predictions found: {len(predictions)}\n")

        if predictions:
            print("Latest malware predictions:")
            print("-" * 60)
            for i, pred in enumerate(predictions[:10], 1):
                print(f"{i:2d}. {pred}")

            if len(predictions) > 10:
                print(f"\n... and {len(predictions) - 10} more")

            # Statistics
            ecosystems = set(p.ecosystem for p in predictions)
            print(f"\nEcosystems: {', '.join(sorted(ecosystems))}")

            statuses = {}
            for pred in predictions:
                statuses[pred.status] = statuses.get(pred.status, 0) + 1
            print(f"Status breakdown: {statuses}")

            # Export to OpenSSF format
            print("\n" + "=" * 60)
            print("Exporting to OpenSSF format...")
            output_dir = client.export_to_openssf_format(predictions)
            print(f"\nFiles exported to: {output_dir}")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
