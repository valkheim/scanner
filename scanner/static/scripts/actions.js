const actionsArea = document.querySelector(".actions-area")
const copyExtractorButtons = document.querySelector(".extractors").querySelectorAll(".action-copy")
const rerunButton = actionsArea.querySelector("#action-rerun")
const deleteButton = actionsArea.querySelector("#action-delete")
const exportButton = actionsArea.querySelector("#action-export")
const hash = document.querySelector("#infos-hash").innerText

copyExtractorButtons.forEach(copyExtractorButton => {
    copyExtractorButton.addEventListener("click", (e) => {
        const nextTextareaContents = e.target.parentElement.parentElement.parentElement.parentElement.nextElementSibling.innerHTML
        navigator.clipboard.writeText(nextTextareaContents)
    })
})

rerunButton.addEventListener('click', () => {
    fetch("/a/" + hash).then(res => {
        window.location.replace(res.url);
    })
})

deleteButton.addEventListener('click', () => {
    fetch("/d/" + hash).then(res => {
        window.location.replace(res.url);
    })
})

exportButton.onclick = () => {
    fetch("/x/" + hash)
        .then(async res => ({
            name: res.headers.get("content-disposition")?.split("=")[1],
            blob: await res.blob()
        }))
        .then(res => {
            const { name, blob } = res
            const url = window.URL.createObjectURL(blob);
            let link = document.createElement("a");
            link.href = url;
            link.download = name;
            link.click();
        })
}
