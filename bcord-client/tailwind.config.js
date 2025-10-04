/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#1e1f22",
        sidebar: "#2b2d31",
        channelbar: "#313338",
        chat: "#383a40",
        accent: "#5865f2"
      }
    }
  },
  plugins: []
}

