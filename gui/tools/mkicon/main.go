// Command mkicon turns icon.svg into icon.ico.
//
// Windows takes the icon for Explorer, the taskbar and a Start menu shortcut
// from a resource compiled into the executable, and not from anything the
// program does at run time. That is why the tray icon was right while the other
// three were the generic one: the tray is drawn by the toolkit from the SVG the
// binary embeds, and the rest of the desktop never asks the program at all.
//
// The .ico is generated rather than drawn, and generated from the SVG rather
// than from a copy of its geometry, so there is one mark and not two that agree
// until somebody edits one of them. It is committed, because .gitattributes has
// expected an .ico here since before there was one and because rasterising at
// build time would put a renderer on the path of every Windows build for a file
// that changes about once a year.
//
// Regenerate with:
//
//	cd gui && go run ./tools/mkicon
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"

	"github.com/fyne-io/oksvg"
	"github.com/srwiley/rasterx"
)

// sizes are what Windows asks for. 16 is the title bar and the task bar's small
// mode, 32 the desktop, 48 the Explorer list, 256 the extra-large view and what
// Windows scales from on a high-DPI display. The ones between are cheap and stop
// Windows scaling 16 up to 24, which is what makes an icon look smeared.
var sizes = []int{16, 20, 24, 32, 40, 48, 64, 128, 256}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mkicon:", err)
		os.Exit(1)
	}
}

func run() error {
	svg, err := os.Open("icon.svg")
	if err != nil {
		return err
	}
	defer svg.Close()

	icon, err := oksvg.ReadIconStream(svg)
	if err != nil {
		return fmt.Errorf("reading icon.svg: %w", err)
	}

	var images [][]byte
	for _, s := range sizes {
		png, err := render(icon, s)
		if err != nil {
			return fmt.Errorf("at %dpx: %w", s, err)
		}
		images = append(images, png)
	}

	out, err := os.Create(filepath.Join("packaging", "icon.ico"))
	if err != nil {
		return err
	}
	defer out.Close()
	if err := writeICO(out, sizes, images); err != nil {
		return err
	}
	fmt.Printf("wrote gui/packaging/icon.ico, %d sizes\n", len(sizes))
	return nil
}

// render rasterises the icon at one size, as a PNG.
//
// PNG rather than the older bitmap form for every entry. Windows has accepted
// PNG inside an .ico since Vista, a bitmap entry carries an AND mask that has to
// be built by hand and got wrong, and the sizes above are small enough that
// nothing is saved by it.
func render(icon *oksvg.SvgIcon, size int) ([]byte, error) {
	icon.SetTarget(0, 0, float64(size), float64(size))

	img := image.NewRGBA(image.Rect(0, 0, size, size))
	scanner := rasterx.NewScannerGV(size, size, img, img.Bounds())
	icon.Draw(rasterx.NewDasher(size, size, scanner), 1)

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeICO assembles the container: a header, one directory entry per image
// saying where it is, and then the images.
func writeICO(f *os.File, sizes []int, images [][]byte) error {
	const dirEntry = 16
	header := struct{ Reserved, Type, Count uint16 }{0, 1, uint16(len(images))}
	if err := binary.Write(f, binary.LittleEndian, header); err != nil {
		return err
	}

	offset := 6 + dirEntry*len(images)
	for i, img := range images {
		// 256 is written as 0: the field is one byte and the format says so.
		dim := byte(sizes[i])
		if sizes[i] >= 256 {
			dim = 0
		}
		entry := struct {
			Width, Height, Colors, Reserved byte
			Planes, Bits                    uint16
			Size, Offset                    uint32
		}{dim, dim, 0, 0, 1, 32, uint32(len(img)), uint32(offset)}
		if err := binary.Write(f, binary.LittleEndian, entry); err != nil {
			return err
		}
		offset += len(img)
	}

	for _, img := range images {
		if _, err := f.Write(img); err != nil {
			return err
		}
	}
	return nil
}
