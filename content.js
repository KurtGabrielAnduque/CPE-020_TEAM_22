const dogImages = [
  "https://brownvethospital.com/wp-content/uploads/2024/02/when-do-dogs-stop-growing.jpg",
  "https://images.wagwalkingweb.com/media/daily_wag/blog_articles/hero/1723114015.705158/popular-dogs-hero-1.jpg"
];

function replaceWithDogs() {
  const images = document.querySelectorAll('img');
  images.forEach(img => {
    // Check if the image is NOT already one of our dog images
    if (!img.src.includes('brownvethospital') && !img.src.includes('wagwalkingweb')) {
      const randomDog = dogImages[Math.floor(Math.random() * dogImages.length)];
      img.src = randomDog;
    }
  });
}

// Run every 500ms to catch new thumbnails while scrolling
setInterval(replaceWithDogs, 500);