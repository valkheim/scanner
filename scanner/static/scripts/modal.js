const openModal = () => {
    const loadingModal = document.querySelector(".modal")
    loadingModal.style.visibility = "visible"
}

document.querySelectorAll(".open-modal").forEach((e) => {
    console.debug("click open modal")
    e.addEventListener('click', () => openModal())
})
