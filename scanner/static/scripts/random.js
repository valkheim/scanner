const rand = (arr) => arr[Math.floor(Math.random() * arr.length)]

window.onload = () => {
    const footerArea = document.querySelector(".footer")
    footerArea.innerText = rand([
        "Present day. present time!",
        "‿( ́ ̵ _-`)‿",
        "ಠ_ಠ",
        "(-(-_(-_-)_-)-)",
        "( -_-)旦~",
        String.raw`¯\_(ツ)_/¯`,
        String.raw`(╯°□°）╯︵ ┻━┻`,
        String.raw`(ヘ･_･)ヘ┳━┳`
    ])
}
