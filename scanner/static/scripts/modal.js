const openModal = () => {
    const loadingModal = document.querySelector(".modal")
    loadingModal.style.visibility = "visible"
}

document.querySelectorAll(".open-modal").forEach((e) => {
    e.addEventListener('click', () => openModal())
})

window.onload = () => {
    const modalImg = document.querySelector(".modal .modal__inner img")
    const id = Math.floor(Math.random() * 7)
    modalImg.src = `/static/img/sleepy/${id}.gif`
}
