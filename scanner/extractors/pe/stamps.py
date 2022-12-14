#!/usr/bin/env python3

import datetime
import sys

from _pe import get_stamps

"""
Extract PE time stamps:
_IMAGE_FILE_HEADER
_IMAGE_IMPORT_DESCRIPTOR
_IMAGE_EXPORT_DIRECTORY
_IMAGE_RESOURCE_DIRECTORY
_IMAGE_DEBUG_DIRECTORY
_IMAGE_BOUND_IMPORT_DESCRIPTOR
_IMAGE_LOAD_CONFIG_DIRECTORY
"""
if __name__ == "__main__":
    if (stamps := get_stamps(sys.argv[1])) is None:
        sys.exit(1)

    print("location,timestamp,utc_timestamp,age_in_days")
    for location, ts in stamps.items():
        utc_time = datetime.datetime.utcfromtimestamp(ts)
        t_delta = (datetime.datetime.today() - utc_time).days
        print(
            location,
            ts,
            utc_time.strftime("%Y-%m-%d %H:%M:%S +00:00 (UTC)"),
            t_delta,
            sep=",",
        )

    sys.exit(0)
