document.addEventListener('DOMContentLoaded', function () {
    var closeButton = document.getElementById('closeToast');
    var toast = document.getElementById('toast');
    if (toast) {
        // Add Tailwind classes to trigger the fade-in animation
        toast.classList.remove('opacity-0');
        toast.classList.add('opacity-100');

        // Set a timeout to close the toast after 30 seconds
        var timeoutId = setTimeout(function () {
            // Remove fade-in class and add fade-out class for exit animation
            toast.classList.remove('opacity-100');
            toast.classList.add('opacity-0');
            setTimeout(function () {
                toast.style.display = 'none';
            }, 300); // Wait for the fade-out animation to complete
        }, 5000); // 5000 milliseconds = 5 seconds

        // Clear the timeout if the close button is clicked
        closeButton.addEventListener('click', function () {
            clearTimeout(timeoutId);
            // Remove fade-in class and add fade-out class for exit animation
            toast.classList.remove('opacity-100');
            toast.classList.add('opacity-0');
            setTimeout(function () {
                toast.style.display = 'none';
            }, 300); // Wait for the fade-out animation to complete
        });
    };
});



// JavaScript
const searchInput = document.getElementById('search-audit');
if (searchInput) {
    const tableRows = document.querySelectorAll('#audit-list tbody tr');
    searchInput.addEventListener('input', function () {
        const searchValue = this.value.toLowerCase();

        tableRows.forEach(row => {
            const rowText = row.textContent.toLowerCase();
            if (rowText.includes(searchValue)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
}


function handleSortChange() {
    const select = document.getElementById('statusFilter');
    const selectedStatus = select.value;
    const table = document.getElementById('audit-list');
    const tbody = table.querySelector('tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));

    // Sort the rows based on the selected status
    rows.sort((a, b) => {
        const statusA = a.cells[2].textContent.trim().toLowerCase();
        const statusB = b.cells[2].textContent.trim().toLowerCase();

        // If the statuses are the same, keep the original order
        if (statusA === statusB) return 0;

        // If the selected status is the same as the first status, it should come first
        if (statusA === selectedStatus) return -1;
        if (statusB === selectedStatus) return 1;

        // If neither status is the selected status, keep the original order
        return 0;
    });

    // Remove all rows from the table body
    while (tbody.firstChild) {
        tbody.removeChild(tbody.firstChild);
    }

    // Append the sorted rows back to the table body
    rows.forEach(row => tbody.appendChild(row));
}


document.addEventListener('DOMContentLoaded', function () {
    const deleteButtons = document.querySelectorAll('[data-toggle="deleteModal"]');
    const deleteModal = document.getElementById('deleteModal');
    const deleteConfirm = document.getElementById('deleteConfirm');
    const deleteCancel = document.getElementById('deleteCancel');
    const auditDeleteMessage = document.getElementById('auditDeleteMessage');
    const initiateAuditButtons = document.querySelectorAll('[data-toggle="initiateAuditModal"]');
    const initiateAuditModal = document.getElementById('initiateAuditModal');
    const initiateAuditConfirm = document.getElementById('initiateAuditConfirm');
    const initiateAuditCancel = document.getElementById('initiateAuditCancel');
    const auditScanMessage = document.getElementById('auditScanMessage');

    if (deleteModal || initiateAuditModal) {

        deleteButtons.forEach(button => {
            button.addEventListener('click', () => {
                // Get the audit name from the clicked button
                const auditName = button.getAttribute('data-audit-name');
                const deleteUrl = button.getAttribute('data-delete-url');

                // Update the modal content with the audit name
                auditDeleteMessage.innerHTML = ` Are you sure you want to delete <b> ${auditName} </b> ?`;
                submitForm.action = deleteUrl

                deleteModal.classList.remove('hidden');
            });
        });

        deleteCancel.addEventListener('click', () => {
            deleteModal.classList.add('hidden');
        });

        initiateAuditButtons.forEach(button => {
            button.addEventListener('click', () => {
                // Get the audit name from the clicked button
                const auditName = button.getAttribute('data-audit-name');
                const initiateAuditUrl = button.getAttribute('data-initiate-audit-url');

                // Update the modal content with the audit name
                auditScanMessage.innerHTML = `Are you sure you want to kick off the Scan for <b> ${auditName} </b> ?`;
                submitForm.action = initiateAuditUrl

                initiateAuditModal.classList.remove('hidden');
            });
        });

        initiateAuditCancel.addEventListener('click', () => {
            initiateAuditModal.classList.add('hidden');
        });

        // Prevent the form from submitting normally
        submitForm.addEventListener('submit', function (event) {
            event.preventDefault();
            // Perform any additional actions before submitting the form
            submitForm.submit(); // Submit the form programmatically
        });

    }

});



// Get the scrollable container
const scrollContainer = document.getElementById('all-audit');

if (scrollContainer) {

    // Add event listener for scroll event on the scrollable container
    scrollContainer.addEventListener('scroll', handleTooltipPosition);

    // Function to handle tooltip position
    function handleTooltipPosition(event) {
        const tooltips = document.querySelectorAll('.triangle-top');
        const actiontooltips = document.querySelectorAll('.action-triangle-top');

        // Iterate through each tooltip and update its position
        tooltips.forEach(tooltip => {
            const triggerElement = tooltip.parentElement;
            const rect = triggerElement.getBoundingClientRect();
            const scrollOffset = scrollContainer.scrollTop;
            const newTop = rect.top - scrollOffset / 200 + 23; // Adjust as needed

            // Update the tooltip position
            tooltip.style.top = `${newTop}px`;
        });

        actiontooltips.forEach(actiontooltip => {
            const triggerElement = actiontooltip.parentElement;
            const rect = triggerElement.getBoundingClientRect();
            const scrollOffset = scrollContainer.scrollTop;
            const newTop = rect.top - scrollOffset / 200 - 34; // Adjust as needed

            // Update the actiontooltip position
            actiontooltip.style.top = `${newTop}px`;
        });
    }
}


document.addEventListener('DOMContentLoaded', function () {
    // Get all the tab buttons
    const tabButtons = document.querySelectorAll('[role="tab"]');
    if (tabButtons) {

        // Get the initially active tab button
        const initialActiveTab = document.querySelector('.active');

        // Function to handle tab activation
        function activateTab(tabButton) {
            // Remove active classes from all tab buttons
            tabButtons.forEach(function (btn) {
                btn.classList.remove('border-blue-500', 'text-blue-600', 'active', 'bg-blue-200');
            });
            // Add active class to the clicked tab button
            tabButton.classList.add('active', 'border-blue-500', 'text-blue-600', 'bg-blue-200');
            // Get the target content panel ID from the data-hs-tab attribute
            const targetPanelId = tabButton.getAttribute('data-hs-tab');
            // Get all the content panels
            const contentPanels = document.querySelectorAll('[role="tabpanel"]');
            // Hide all content panels
            contentPanels.forEach(function (panel) {
                panel.classList.add('hidden');
            });
            // Show the target content panel
            const targetPanel = document.querySelector(targetPanelId);
            targetPanel.classList.remove('hidden');
        }

        // Add click event listeners to each tab button
        tabButtons.forEach(function (button) {
            button.addEventListener('click', function (event) {
                event.preventDefault(); // Prevent default link behavior
                activateTab(this);
            });
        });

        // Ensure the initially active tab's content panel is displayed
        if (initialActiveTab) {
            activateTab(initialActiveTab);
        }
    }
});


// generate report
const generatePdfBtn = document.getElementById('generate-report');
const downloadIconSvg = document.getElementById('download-icon-svg');
const loadingIconSvg = document.getElementById('loading-icon-svg');
const MAX_ATTEMPTS = 10; // Maximum number of attempts to fetch the download
if (generatePdfBtn) {
    document.getElementById('generate-report').addEventListener('click', function() {
        var auditId = this.dataset.auditId;
        var auditName = this.dataset.auditName;
        downloadIconSvg.classList.add('hidden');
        loadingIconSvg.classList.remove('hidden');
        fetch(`/report/${auditId}`, { method: 'GET' })
            .then(response => {
                if (response.status == 200) {
                    return response.text();
            } else {
                downloadIconSvg.classList.remove('hidden');
                loadingIconSvg.classList.add('hidden');
                throw new Error('Failed to generate PDF');
            }
            })
            .then(jobId => {
            let attempts = 0;
            const checkDownloadInterval = setInterval(() => {
                fetch(`/report/${auditId}/download/${jobId}`, { method: 'GET' })
                .then(response => {
                    if (response.status === 200) {
                    clearInterval(checkDownloadInterval);
                    return response.blob();
                    } else {
                    return response.text();
                    }
                })
                .then(data => {
                    if (typeof data === 'string') {
                        attempts++;
                        if (attempts >= MAX_ATTEMPTS) {
                            clearInterval(checkDownloadInterval);
                            console.log('Maximum attempts reached, terminating PDF download');
                            downloadIconSvg.classList.remove('hidden');
                            loadingIconSvg.classList.add('hidden');
                        } else {
                            console.log(data);
                        }
                    } else {
                    downloadIconSvg.classList.remove('hidden');
                    loadingIconSvg.classList.add('hidden');
                    const downloadUrl = window.URL.createObjectURL(new Blob([data]));
                    const link = document.createElement('a');
                    link.href = downloadUrl;
                    link.download = `${auditName}-report.pdf`;
                    link.click();
                    }
                })
                .catch(error => console.error(error));
            }, 5000);
            })
            .catch(error => console.error(error));
        });
    }




const scanProgress = document.getElementById('progress-circle');
if (scanProgress){
    function updateProgress() {
        var auditId = scanProgress.dataset.auditId;  // Access the audit ID from the data attribute
        fetch(`/audit/progress/${auditId}`)
            .then(response => response.json())
            .then(data => {
                const progress = data.progress;
                const progressBar = document.getElementById('progress-bar');
                const progressText = document.getElementById('progress-text');
                
                // Update the stroke-dashoffset to reflect the new progress value
                progressBar.style.strokeDashoffset = 100 - progress;
                
                // Update the progress text
                progressText.textContent = progress + '%';

                // Check if the status is 'finished', if so, stop the interval
                if (data.status === 'finished') {
                    clearInterval(progressInterval);
                }
            })
            .catch(error => console.error('Error fetching progress:', error));
        }

        // Set an interval to refresh the progress periodically
        const progressInterval = setInterval(updateProgress, 20000);  // Update every 20 seconds

        // Call updateProgress initially
        updateProgress();
    }



    
function copyText() {
    const textToCopy = document.getElementById('vulnerability-data').innerText;
    navigator.clipboard.writeText(textToCopy)
        .then(() => {
            document.getElementById('copy-data').textContent = 'Copied';
                    setTimeout(() => {
                        document.getElementById('copy-data').textContent = 'Copy Evidence';
                    }, 3000); // Change back to 'Copy Copy Evidence' after 3 seconds
                })
        .catch((error) => {
            console.error('Error copying text:', error);
            alert('Failed to copy text. Please try again.');
        });
}


window.onload = function() {
    const imageElement = document.querySelector('.hoverImage');
    if (imageElement) {
      const handleMouseMove = (e) => {
        let rect = imageElement.getBoundingClientRect();
        let x = e.clientX - rect.left;
        let y = e.clientY - rect.top;

        let dx = (x - rect.width / 2) / (rect.width / 2);
        let dy = (y - rect.height / 2) / (rect.height / 2);

        imageElement.style.transform = `perspective(500px) rotateY(${dx * 4}deg) rotateX(${-dy * 4}deg)`;
      };

      const handleMouseLeave = () => {
        imageElement.style.transform = "";
      };

      imageElement.addEventListener('mousemove', handleMouseMove);
      imageElement.addEventListener('mouseleave', handleMouseLeave);
    }
  }

