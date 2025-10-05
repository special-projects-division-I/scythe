# SCYTHE GUI Icons

This directory contains application icons for the SCYTHE C2 Controller GUI.

## Required Icons

For a complete Tauri application, you should provide the following icon formats:

### Windows
- `icon.ico` - Windows icon file (multiple sizes)
- `32x32.png` - Small icon
- `128x128.png` - Medium icon
- `128x128@2x.png` - High DPI medium icon

### macOS
- `icon.icns` - macOS icon file
- `32x32.png` - Small icon
- `128x128.png` - Medium icon
- `128x128@2x.png` - High DPI medium icon

### Linux
- `32x32.png` - Small icon
- `128x128.png` - Medium icon
- `128x128@2x.png` - High DPI medium icon

## Icon Design Guidelines

- **Style**: Modern, professional security tool aesthetic
- **Colors**: Dark theme with blue/cyan accents
- **Symbol**: Consider using a scythe or abstract security symbol
- **Resolution**: Vector-based design that scales well
- **Background**: Transparent background for PNG files

## Generating Icons

You can use tools like:
- **Online**: Favicon.io, Canva, or specialized icon generators
- **Desktop**: GIMP, Photoshop, or IconWorkshop
- **CLI**: `icotool` (Linux) for Windows icons

## Temporary Setup

For development, Tauri will use default icons if these are not provided. For production builds, add properly sized icons to this directory.

## Example Commands

```bash
# Using ImageMagick to create different sizes from a source SVG
convert scythe-icon.svg -resize 32x32 32x32.png
convert scythe-icon.svg -resize 128x128 128x128.png
convert scythe-icon.svg -resize 256x256 128x128@2x.png

# Using icotool for Windows icons
icotool -c -o icon.ico 32x32.png 128x128.png 256x256.png
```
