package ec

import (
	"crypto-dstu/gf2m"
	"encoding/hex"
	"fmt"
)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(fmt.Sprintf("invalid hex string %q: %v", s, err))
	}
	return b
}

func mustFromHex(s string, words int) gf2m.Element {
	e, err := gf2m.FromHex(s, words)
	if err != nil {
		panic(fmt.Sprintf("invalid field element hex %q (words=%d): %v", s, words, err))
	}
	return e
}

// Standard DSTU 4145-2002 elliptic curves

// DSTU_PB_257 returns the DSTU curve over GF(2^257)
func DSTU_PB_257() *Curve {
	words := 9 // ceil(257/32) = 9

	a := mustFromHex("0", words)
	b := mustFromHex("01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", words)
	gx := mustFromHex("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", words)
	gy := mustFromHex("010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", words)

	n := mustDecodeHex("800000000000000000000000000000006759213AF182E987D3E17714907D470D")

	return NewCurve(257, gf2m.ModBits257, a, b, gx, gy, n, 4)
}

// DSTU_PB_431 returns the DSTU curve over GF(2^431)
func DSTU_PB_431() *Curve {
	words := 14 // ceil(431/32) = 14

	a := mustFromHex("1", words)
	b := mustFromHex("003CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", words)
	gx := mustFromHex("1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D", words)
	gy := mustFromHex("70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9", words)

	n := mustDecodeHex("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF")

	return NewCurve(431, gf2m.ModBits431, a, b, gx, gy, n, 2)
}

// DSTU_PB_163 returns the DSTU curve over GF(2^163)
// Parameters verified from ikripaka/dstu4145-rust and ukurwa4145
func DSTU_PB_163() *Curve {
	words := 6 // ceil(163/32) = 6

	a := mustFromHex("1", words)
	b := mustFromHex("5FF6108462A2DC8210AB403925E638A19C1455D21", words)
	gx := mustFromHex("2E2F85F5DD74CE983A5C4237229DAF8A3F35823BE", words)
	gy := mustFromHex("3826F008A8C51D7B95284D9D03FF0E00CE2CD723A", words)

	n := mustDecodeHex("0400000000000000000002BEC12BE2262D39BCF14D")

	return NewCurve(163, gf2m.ModBits163, a, b, gx, gy, n, 2)
}

// DSTU_PB_167 returns the DSTU curve over GF(2^167)
func DSTU_PB_167() *Curve {
	words := 6 // ceil(167/32) = 6

	a := mustFromHex("1", words)
	b := mustFromHex("6EE3CEEB230811759F20518A0930F1A4315A827DAC", words)

	gx := mustFromHex("7A1F6653786A68192803910A3D30B2A2018B21CD54", words)
	gy := mustFromHex("5F49EB26781C0EC6B8909156D98ED435E45FD59918", words)

	n := mustDecodeHex("3FFFFFFFFFFFFFFFFFFFFFB12EBCC7D7F29FF7701F")

	return NewCurve(167, gf2m.ModBits167, a, b, gx, gy, n, 2)
}

// DSTU_PB_173 returns the DSTU curve over GF(2^173)
// Parameters from ikripaka/dstu4145-rust
func DSTU_PB_173() *Curve {
	words := 6 // ceil(173/32) = 6

	a := mustFromHex("0", words)
	b := mustFromHex("108576C80499DB2FC16EDDF6853BBB278F6B6FB437D9", words)
	gx := mustFromHex("04D41A619BCC6EADF0448FA22FAD567A9181D37389CA", words)
	gy := mustFromHex("10B51CC12849B234C75E6DD2028BF7FF5C1CE0D991A1", words)

	n := mustDecodeHex("0800000000000000000000189B4E67606E3825BB2831")

	return NewCurve(173, gf2m.ModBits173, a, b, gx, gy, n, 2)
}

// DSTU_PB_179 returns the DSTU curve over GF(2^179)
// Parameters from ikripaka/dstu4145-rust
func DSTU_PB_179() *Curve {
	words := 6 // ceil(179/32) = 6

	a := mustFromHex("1", words)
	b := mustFromHex("4A6E0856526436F2F88DD07A341E32D04184572BEB710", words)
	gx := mustFromHex("6BA06FE51464B2BD26DC57F48819BA9954667022C7D03", words)
	gy := mustFromHex("25FBC363582DCEC065080CA8287AAFF09788A66DC3A9E", words)

	n := mustDecodeHex("03FFFFFFFFFFFFFFFFFFFFFFB981960435FE5AB64236EF")

	return NewCurve(179, gf2m.ModBits179, a, b, gx, gy, n, 2)
}

// DSTU_PB_191 returns the DSTU curve over GF(2^191)
// Parameters from ikripaka/dstu4145-rust
func DSTU_PB_191() *Curve {
	words := 6 // ceil(191/32) = 6

	a := mustFromHex("1", words)
	b := mustFromHex("7BC86E2102902EC4D5890E8B6B4981ff27E0482750FEFC03", words)
	gx := mustFromHex("714114B762F2FF4A7912A6D2AC58B9B5C2FCFE76DAEB7129", words)
	gy := mustFromHex("29C41E568B77C617EFE5902F11DB96FA9613CD8D03DB08DA", words)

	n := mustDecodeHex("40000000000000000000000069A779CAC1DABC6788F7474F")

	return NewCurve(191, gf2m.ModBits191, a, b, gx, gy, n, 2)
}

// DSTU_PB_233 returns the DSTU curve over GF(2^233)
// Polynomial fixed to x^233+x^9+x^4+x+1 per DSTU 4145-2002 Table 1
func DSTU_PB_233() *Curve {
	words := 8 // ceil(233/32) = 8

	a := mustFromHex("1", words)
	b := mustFromHex("06973B15095675534C7CF7E64A21BD54EF5DD3B8A0326AA936ECE454D2C", words)
	gx := mustFromHex("3FCDA526B6CDF83BA1118DF35B3C31761D3545F32728D003EEB25EFE96", words)
	gy := mustFromHex("9CA8B57A934C54DEEDA9E54A7BBAD95E3B2E91C54D32BE0B9DF96D8D35", words)

	n := mustDecodeHex("01000000000000000000000000000013E974E72F8A6922031D2603CFE0D7")

	return NewCurve(233, gf2m.ModBits233, a, b, gx, gy, n, 2)
}

// DSTU_PB_307 returns the DSTU curve over GF(2^307)
// Parameters from ikripaka/dstu4145-rust
func DSTU_PB_307() *Curve {
	words := 10 // ceil(307/32) = 10

	a := mustFromHex("1", words)
	b := mustFromHex("393C7F7D53666B5054B5E6C6D3DE94F4296C0C599E2E2E241050DF18B6090BDC90186904968BB", words)
	gx := mustFromHex("216EE8B189D291A0224984C1E92F1D16BF75CCD825A087A239B276D3167743C52C02D6E7232AA", words)
	gy := mustFromHex("5D9306BACD22B7FAEB09D2E049C6E2866C5D1677762A8F2F2DC9A11C7F7BE8340AB2237C7F2A0", words)

	n := mustDecodeHex("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC079C2F3825DA70D390FBBA588D4604022B7B7")

	return NewCurve(307, gf2m.ModBits307, a, b, gx, gy, n, 2)
}

// DSTU_PB_367 returns the DSTU curve over GF(2^367)
// Parameters from ikripaka/dstu4145-rust
func DSTU_PB_367() *Curve {
	words := 12 // ceil(367/32) = 12

	a := mustFromHex("1", words)
	b := mustFromHex("43FC8AD242B0B7A6F3D1627AD5654447556B47BF6AA4A64B0C2AFE42CADAB8F93D92394C79A79755437B56995136", words)
	gx := mustFromHex("324A6EDDD512F08C49A99AE0D3F961197A76413E7BE81A400CA681E09639B5FE12E59A109F78BF4A373541B3B9A1", words)
	gy := mustFromHex("1AB597A5B4477F59E39539007C7F977D1A567B92B043A49C6B61984C3FE3481AAF454CD41BA1F051626442B3C10", words)

	n := mustDecodeHex("40000000000000000000000000000000000000000000009C300B75A3FA824F22428FD28CE8812245EF44049B2D49")

	return NewCurve(367, gf2m.ModBits367, a, b, gx, gy, n, 2)
}

// AllCurves returns a map of all standard DSTU curves by name.
func AllCurves() map[string]*Curve {
	return map[string]*Curve{
		"DSTU_PB_163": DSTU_PB_163(),
		"DSTU_PB_167": DSTU_PB_167(),
		"DSTU_PB_173": DSTU_PB_173(),
		"DSTU_PB_179": DSTU_PB_179(),
		"DSTU_PB_191": DSTU_PB_191(),
		"DSTU_PB_233": DSTU_PB_233(),
		"DSTU_PB_257": DSTU_PB_257(),
		"DSTU_PB_307": DSTU_PB_307(),
		"DSTU_PB_367": DSTU_PB_367(),
		"DSTU_PB_431": DSTU_PB_431(),
	}
}
