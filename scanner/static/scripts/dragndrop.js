const dropArea = document.querySelector(".drag-area")
const dragText = dropArea.querySelector("header")
const button = dropArea.querySelector("button")
const input = dropArea.querySelector("input")

button.onclick = () => input.click()

input.addEventListener("change", function () {
    dropArea.classList.add("active")
    handleFile(this.files[0])
})

dropArea.addEventListener("dragover", (e) => {
    e.preventDefault()
    dropArea.classList.add("active")
    dragText.textContent = "Release to upload file"
})

dropArea.addEventListener("dragleave", () => {
    dropArea.classList.remove("active")
    dragText.textContent = "Drag & Drop to upload file"
})

dropArea.addEventListener("drop", (e) => {
    e.preventDefault()
    handleFile(e.dataTransfer.files[0])
})

function handleFile(file) {
    const formData = new FormData()
    formData.append("file", file)
    const requestOptions = {
        method: "POST",
        files: file,
        body: formData,
    }

    fetch("/upload", requestOptions).then(
        (response) => {
            window.location.replace(response.url);
        }
    )
}
