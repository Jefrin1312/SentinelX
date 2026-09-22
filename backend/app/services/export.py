"""CSV evidence export helpers.

Used by the alerts / events / audit-log export endpoints so the SOC can pull
filtered results into spreadsheets for evidence, sign-off, and external
reporting. Rows are built in the caller — this module only serialises.
"""

import csv
import io

from fastapi import Response


def csv_response(filename: str, headers: list[str], rows: list[list[object]]) -> Response:
    """Serialise ``rows`` to CSV and return it as a downloadable attachment."""
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    writer.writerows(rows)
    buffer.seek(0)
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )