const rand = (arr) => arr[Math.floor(Math.random() * arr.length)]

window.addEventListener("load", () => {
    const footerArea = document.querySelector("footer")
    footerArea.innerText = rand([
        "Present day. present time!",
        "‿( ́ ̵ _-`)‿",
        "ಠ_ಠ",
        "(-(-_(-_-)_-)-)",
        "( -_-)旦~",
        "d[ o_0 ]b",
        "•͡˘㇁•͡˘",
        "(<(<>(<>.(<>..<>).<>)<>)>)",
        "【ツ】",
        "ლ(ಠ益ಠ)ლ",
        "( ͡° ͜ʖ ͡°)",
        "(⌐■_■)",
        "／人 ◕‿‿◕ 人＼",
        "ᕦ(ò_óˇ)ᕤ",
        "ᕕ( ᐛ )ᕗ",
        "(°Д°)",
        "(Ͼ˳Ͽ)..!!!",
        "≧◔◡◔≦",
        "╰( ⁰ ਊ ⁰ )━☆ﾟ.*･｡ﾟ",
        String.raw`＼（〇_ｏ）／`,
        String.raw`(\/)(Ö,,,,Ö)(\/)`,
        String.raw`¯\_(ツ)_/¯`,
        String.raw`(╯°□°）╯︵ ┻━┻`,
        String.raw`(ヘ･_･)ヘ┳━┳`
    ])
})
