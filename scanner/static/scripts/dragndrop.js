const dropArea = document.querySelector(".drag-area")
const dragText = dropArea.querySelector("header")
const button = dropArea.querySelector("button")
const input = dropArea.querySelector("input")

button.onclick = () => {
    input.click()
}

input.addEventListener("change", function () {
    dropArea.classList.add("active")
    handleFile(this.files[0])
})

dropArea.addEventListener("dragover", (event) => {
    event.preventDefault()
    dropArea.classList.add("active")
    dragText.textContent = "Release to Upload File"
})

dropArea.addEventListener("dragleave", () => {
    dropArea.classList.remove("active")
    dragText.textContent = "Drag & Drop to Upload File"
})

dropArea.addEventListener("drop", (event) => {
    event.preventDefault()
    handleFile(event.dataTransfer.files[0])
})

function handleFile(file) {
    const formData = new FormData()
    formData.append("file", file)
    const requestOptions = {
        mode: "no-cors",
        method: "POST",
        files: file,
        body: formData,
    }

    fetch("http://localhost:5000/upload", requestOptions).then(
        (response) => {
            window.location.replace(response.url);
        }
    )
}
