const actionsArea = document.querySelector(".actions-area")
const rerunButton = actionsArea.querySelector("#action-rerun")
const saveButton = actionsArea.querySelector("#action-save")
const hash = document.querySelector("#infos-hash").innerText

rerunButton.addEventListener('click', () => {
    console.log("click rerun")
    fetch("/a/" + hash).then((res) => {
        console.log("rerun")
        window.location.replace(res.url);
    })
})

saveButton.onclick = () => alert("not implemented")
