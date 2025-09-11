import { initializeApp } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-app.js";
import { getAuth } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-auth.js";
import { getFirestore } from "https://www.gstatic.com/firebasejs/12.2.1/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyAc_CPKw8-Mv6Ut-IFuEsryJjuWTbb8Bak",
  authDomain: "juego-de-mesa-c50b5.firebaseapp.com",
  projectId: "juego-de-mesa-c50b5",
  storageBucket: "juego-de-mesa-c50b5.firebasestorage.app",
  messagingSenderId: "504413022472",
  appId: "1:504413022472:web:8baab790435273eb3924bd",
  measurementId: "G-SRRTZFM3L9"
};

const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);