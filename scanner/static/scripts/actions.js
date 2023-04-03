const actionsArea = document.querySelector(".actions-area")
const rerunButton = actionsArea.querySelector("#action-rerun")
const saveButton = actionsArea.querySelector("#action-save")
const hash = document.querySelector("#infos-hash").innerText

rerunButton.addEventListener('click', () => {
    fetch("/a/" + hash).then(res => {
        window.location.replace(res.url);
    })
})

saveButton.onclick = () => {
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
