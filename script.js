// Function to handle sending chat messages in the forum
function sendMessage() {
    const chatInput = document.getElementById('chatInput');
    const chatMessages = document.getElementById('chat-messages');

    if (chatInput.value.trim() !== "") {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('chat-message');
        messageDiv.innerText = chatInput.value;

        chatMessages.appendChild(messageDiv);
        chatInput.value = ""; // Clear input after sending
        chatMessages.scrollTop = chatMessages.scrollHeight; // Auto-scroll to latest message
    }
}

// Function to handle submitting feedback
// Function to handle submitting feedback
async function submitFeedback(event) {
  event.preventDefault();

  const userId = document.getElementById('userId').value;
  const eventName = document.getElementById('eventName').value; 
  const likes = document.getElementById('likes').value;
  const complaints = document.getElementById('complaints').value || null;
  const suggestions = document.getElementById('suggestions').value || null;
  const rating = document.getElementById('rating').value;

  if (!userId || !eventName || !rating) {
      alert('User ID, Event Name, and Rating are required.');
      return;
  }

  const feedbackData = {
      userId,
      eventName, 
      likes,
      complaints,
      suggestions,
      rating
  };

  try {
      const response = await fetch('http://localhost:5000/feedback', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(feedbackData)
      });

      const result = await response.json();

      if (response.ok) {
          alert('Feedback submitted successfully!');
      } else {
          alert(`Error: ${result.error || 'Unable to submit feedback'}`);
      }
  } catch (error) {
      alert('An error occurred while submitting feedback.');
      console.error('Error:', error);
  }
}

// Attach submitFeedback to the form's submit event
document.querySelector('#feedbackForm').addEventListener('submit', submitFeedback);

  
document.getElementById('mediaUpload').addEventListener('change', uploadMedia);

function uploadMedia() {
    const input = document.getElementById('mediaUpload');
    const file = input.files[0];

    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const mediaContainer = document.getElementById('mediaPreview');
            const mediaItem = document.createElement('div');
            mediaItem.classList.add('media-item');

            const img = document.createElement('img');
            img.src = e.target.result;
            img.classList.add('media-item');
            img.onclick = () => openFullscreen(e.target.result);

            mediaItem.appendChild(img);
            mediaContainer.appendChild(mediaItem);
        };
        reader.readAsDataURL(file);
    }
}

function openFullscreen(src) {
    const fullscreenView = document.getElementById('fullscreenView');
    const fullscreenImage = document.getElementById('fullscreenImage');
    fullscreenView.style.display = 'flex';
    fullscreenImage.src = src;
}

function closeFullscreen() {
    document.getElementById('fullscreenView').style.display = 'none';
}

function deleteMedia() {
    const fullscreenView = document.getElementById('fullscreenView');
    const mediaContainer = document.getElementById('mediaPreview');
    const fullscreenImage = document.getElementById('fullscreenImage');

    const mediaItems = mediaContainer.getElementsByTagName('img');
    for (let i = 0; i < mediaItems.length; i++) {
        if (mediaItems[i].src === fullscreenImage.src) {
            mediaContainer.removeChild(mediaItems[i].parentElement);
            break;
        }
    }

    closeFullscreen();
}

function downloadMedia() {
    const link = document.createElement('a');
    link.href = document.getElementById('fullscreenImage').src;
    link.download = 'downloaded_image.jpg';
    link.click();
}
