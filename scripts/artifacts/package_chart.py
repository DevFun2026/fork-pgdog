"""Package a temporary chart copy paired to one verified image digest."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import yaml
from artifacts.chart_checks import validate_rendered_chart
from artifacts.release_receipt import validate_digest, validate_version


def package_chart(source: Path, image_digest: str, image_version: str, chart_version: str, output: Path) -> Path:
    validate_digest(image_digest); validate_version(image_version); validate_version(chart_version)
    output.mkdir(parents=True, exist_ok=True)
    destination = output / f"fork-pgdog-{chart_version}.tgz"
    if destination.exists():
        raise ValueError("Chart package already exists; refusing overwrite")
    with tempfile.TemporaryDirectory(prefix="fork-pgdog-package-") as directory:
        chart = Path(directory) / "fork-pgdog"
        shutil.copytree(source, chart)
        metadata = yaml.safe_load((chart / "Chart.yaml").read_text())
        metadata.update(version=chart_version, appVersion=image_version)
        (chart / "Chart.yaml").write_text(yaml.safe_dump(metadata, sort_keys=False))
        values = yaml.safe_load((chart / "values.yaml").read_text())
        values["image"].update(repository="ghcr.io/devfun2026/fork-pgdog", digest=image_digest, tag=image_version)
        (chart / "values.yaml").write_text(yaml.safe_dump(values, sort_keys=False))
        fixture = yaml.safe_load((chart / "examples/values.yaml").read_text())
        for key, value in fixture.items():
            values[key].update(value)
        fixture_path = chart / "examples/values.yaml"
        subprocess.run(["helm", "lint", str(chart), "--strict", "--values", str(fixture_path)], check=True, capture_output=True)
        rendered = subprocess.run(["helm", "template", "artifact-check", str(chart), "--values", str(fixture_path)], check=True, capture_output=True, text=True)
        validate_rendered_chart(list(yaml.safe_load_all(rendered.stdout)), values)
        subprocess.run(["helm", "package", str(chart), "--destination", str(output)], check=True, capture_output=True)
    return destination
