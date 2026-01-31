#!/usr/bin/env python3
"""
GPS Metadata (EXIF) Scanner for Pythonista
============================================

PURPOSE:
Tests for Information Disclosure vulnerability (Bugcrowd VRT: P3/P4)
Checks if uploaded images leak GPS coordinates via EXIF metadata.

VULNERABILITY:
If a website allows image uploads and doesn't strip EXIF data, users can
download images and extract the photographer's exact location (house, office, etc.)

BUGCROWD VRT CLASSIFICATION:
- Category: Sensitive Data Exposure
- Subcategory: EXIF Geolocation Data Present
- Priority: P3 (Medium) if sensitive user data, P4 (Low) if low-risk context

USAGE IN PYTHONISTA:
1. Run this script on your iPhone
2. Select an image from your camera roll
3. Script shows if GPS coordinates are embedded
4. Use this logic to test bug bounty targets

ATTACK SCENARIO:
1. Upload image to target website (profile pic, product photo, etc.)
2. Download the image from the website
3. Run this scanner on the downloaded image
4. If GPS data still present → Information Disclosure vulnerability
5. Write report using templates/BUGCROWD_TEMPLATE.md

REAL-WORLD EXAMPLES:
- Twitter: STRIPS EXIF (✅ secure)
- Facebook: STRIPS EXIF (✅ secure)
- Instagram: STRIPS EXIF (✅ secure)
- Many small business sites: DON'T STRIP (❌ vulnerable)

LEARN → DO → TEACH:
1. Learn: Understand what EXIF is and why it's dangerous
2. Do: Test this on bug bounty programs, find real leaks
3. Teach: Share findings, improve this script, mentor others
"""

import photos
import PIL.Image
from PIL.ExifTags import TAGS, GPSTAGS
import console

def get_exif_data(image):
    """
    Extracts all metadata from an image.

    Returns:
        dict: EXIF data with human-readable tags
    """
    exif_data = {}
    info = image._getexif()

    if info:
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)

            # Special handling for GPS data
            if decoded == "GPSInfo":
                gps_data = {}
                for t in value:
                    sub_decoded = GPSTAGS.get(t, t)
                    gps_data[sub_decoded] = value[t]
                exif_data[decoded] = gps_data
            else:
                exif_data[decoded] = value

    return exif_data


def convert_gps_to_decimal(gps_coords, gps_ref):
    """
    Convert GPS coordinates from degrees/minutes/seconds to decimal format.

    Args:
        gps_coords: Tuple of (degrees, minutes, seconds)
        gps_ref: Reference ('N', 'S', 'E', 'W')

    Returns:
        float: Decimal coordinate
    """
    degrees = gps_coords[0]
    minutes = gps_coords[1] / 60.0
    seconds = gps_coords[2] / 3600.0

    decimal = degrees + minutes + seconds

    # Negative for South and West
    if gps_ref in ['S', 'W']:
        decimal = -decimal

    return decimal


def extract_gps_coordinates(exif_data):
    """
    Extract and convert GPS coordinates to decimal format.

    Returns:
        tuple: (latitude, longitude) or (None, None) if not found
    """
    if 'GPSInfo' not in exif_data:
        return None, None

    gps_info = exif_data['GPSInfo']

    # Check if required GPS data is present
    if 'GPSLatitude' not in gps_info or 'GPSLongitude' not in gps_info:
        return None, None

    lat = convert_gps_to_decimal(
        gps_info['GPSLatitude'],
        gps_info['GPSLatitudeRef']
    )

    lon = convert_gps_to_decimal(
        gps_info['GPSLongitude'],
        gps_info['GPSLongitudeRef']
    )

    return lat, lon


def check_other_sensitive_metadata(exif_data):
    """
    Check for other potentially sensitive EXIF fields.

    Returns:
        list: Sensitive fields found
    """
    sensitive_fields = []

    # Common sensitive EXIF tags
    risky_tags = [
        'Make',           # Camera manufacturer (device fingerprinting)
        'Model',          # Camera model (device fingerprinting)
        'Software',       # Software used (version disclosure)
        'DateTime',       # When photo was taken (temporal correlation)
        'Artist',         # Photographer name (PII)
        'Copyright',      # Copyright holder (PII)
        'UserComment',    # User-added comments (potential PII)
    ]

    for tag in risky_tags:
        if tag in exif_data:
            sensitive_fields.append(f"{tag}: {exif_data[tag]}")

    return sensitive_fields


def analyze_image():
    """
    Main scanner function - picks image and analyzes metadata.
    """
    print("=" * 50)
    print("🔍 GPS EXIF SCANNER - Bug Bounty Edition")
    print("=" * 50)
    print("\nSelect an image to scan for metadata leaks...\n")

    # 1. Pick an image from iPhone photo library
    img_asset = photos.pick_asset()

    if not img_asset:
        print("❌ No image selected. Exiting.")
        return

    # 2. Convert to PIL Image
    img = img_asset.get_image()
    exif = get_exif_data(img)

    # 3. Check for GPS data
    print("\n" + "=" * 50)
    print("📍 GPS COORDINATE CHECK")
    print("=" * 50)

    if 'GPSInfo' in exif:
        lat, lon = extract_gps_coordinates(exif)

        if lat and lon:
            print("🚨 VULNERABILITY FOUND: GPS Metadata Present!")
            print(f"\n   Latitude:  {lat}")
            print(f"   Longitude: {lon}")
            print(f"\n   Google Maps: https://www.google.com/maps?q={lat},{lon}")
            print("\n   ⚠️  If this image was uploaded to a website and")
            print("   this data is still present, it's an Information")
            print("   Disclosure vulnerability (Bugcrowd VRT: P3/P4)")
        else:
            print("⚠️  GPSInfo tag exists but coordinates unreadable")
    else:
        print("✅ SECURE: No GPS data found in this image")

    # 4. Check for other sensitive metadata
    print("\n" + "=" * 50)
    print("🔐 OTHER METADATA CHECK")
    print("=" * 50)

    sensitive = check_other_sensitive_metadata(exif)

    if sensitive:
        print("⚠️  Found potentially sensitive metadata:\n")
        for field in sensitive:
            print(f"   - {field}")
        print("\n   Note: These may be acceptable depending on context,")
        print("   but worth checking program scope.")
    else:
        print("✅ No obvious sensitive metadata found")

    # 5. Full EXIF dump (for advanced analysis)
    print("\n" + "=" * 50)
    print("📋 FULL EXIF DATA")
    print("=" * 50)

    if exif:
        print("\nComplete metadata (for manual review):\n")
        for tag, value in exif.items():
            if tag != 'GPSInfo':  # Already displayed above
                # Truncate long values
                value_str = str(value)
                if len(value_str) > 60:
                    value_str = value_str[:60] + "..."
                print(f"   {tag}: {value_str}")
    else:
        print("\n✅ No EXIF data found (image is clean)")

    # 6. Bug bounty guidance
    print("\n" + "=" * 50)
    print("🎯 BUG BOUNTY TESTING WORKFLOW")
    print("=" * 50)
    print("""
1. Take photo with GPS enabled on your iPhone
2. Upload to target website (profile pic, product image, etc.)
3. Download the image back from the website
4. Run this scanner on the downloaded image
5. If GPS data still present → Write report!

REPORT TEMPLATE:
- Use: templates/BUGCROWD_TEMPLATE.md
- VRT Category: Sensitive Data Exposure
- Subcategory: EXIF Geolocation Data Present
- Priority: P3 (if user data) or P4 (if low-risk context)
- Impact: Attackers can track users' physical location

MITIGATION:
Website should strip EXIF data server-side using:
- Python: Pillow with img.save(..., exif=b"")
- PHP: imagecreatefromjpeg() + imagejpeg()
- JavaScript: exif-js library (client-side, less secure)
""")

    print("\n" + "=" * 50)
    print("Happy hunting! 🎯")
    print("=" * 50)


if __name__ == "__main__":
    # Interactive mode for Pythonista
    analyze_image()
