/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    fontFamily: {
      'sans': ['Open Sans', 'sans-serif'],
      'display': ['Parkinsans', 'sans-serif']
    },
    extend: {
      colors: {
        primary: {
          DEFAULT: '#178EB9',
          dark: '#127294',
          light: '#a8c5cd',
          foreground: '#FFFFFF'
        },
        secondary: {
          DEFAULT: '#FC7C54',
          dark: '#BD4724',
          light: '#FBF7EE'
        },
        naturalLight: '#FBF7EE',
        beige: '#EFE4D0',
        darkBeige: '#504838',
        lightBurntOrange: '#FC7C54',
        burntOrange: '#BD4724',
        'pale-cyan': '#a8c5cd',
        vividSkyBlue: '#178EB9',
        darkBlue: '#127294',
        goldenYellow: '#FEDC25',
        mighty: {
          'dark-gray': '#353733',
        }
      },
      animation: {
        'fade-in': 'fadeIn 0.3s ease-out',
        'slide-in': 'slideIn 0.3s ease-out',
        'spin-slow': 'spin 0.8s linear infinite'
      },
      keyframes: {
        fadeIn: {
          'from': { opacity: '0', transform: 'translateY(10px)' },
          'to': { opacity: '1', transform: 'translateY(0)' }
        },
        slideIn: {
          'from': { transform: 'translateX(-100%)' },
          'to': { transform: 'translateX(0)' }
        }
      }
    },
  },
  plugins: [
    require('@tailwindcss/forms')
  ],
}