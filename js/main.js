import { auth, db } from "./firebaseApp.js";
import {
  signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, onAuthStateChanged
} from "https://www.gstatic.com/firebasejs/12.2.1/firebase-auth.js";
import {
  doc, setDoc, getDoc, updateDoc, onSnapshot, collection, addDoc, query, orderBy, getDocs
} from "https://www.gstatic.com/firebasejs/12.2.1/firebase-firestore.js";

/* ================= VARIABLES ================= */
let tablero = ["","","","","","","","",""];
let turno = "X";
let ganador = null;
let partidaActualRef = null;

/* ================= DOM ================= */
const pantallaLogin = document.getElementById("pantallaLogin");
const pantallaPartidas = document.getElementById("pantallaPartidas");
const pantallaJuego = document.getElementById("pantallaJuego");
const pantallaAmigos = document.getElementById("pantallaAmigos");

const mensajeGanadorDiv = document.getElementById("mensajeGanador");
const jugadorXNombre = document.getElementById("jugadorXNombre");
const jugadorONombre = document.getElementById("jugadorONombre");
const codigoPartidaCreada = document.getElementById("codigoPartida");
const tableroDiv = document.getElementById("tablero");
const chatMensajes = document.getElementById("chatMensajes");
const mensajeInput = document.getElementById("mensajeInput");

const amigosParaInvitarDiv = document.getElementById("amigosParaInvitar");
const contenidoAmigos = document.getElementById("contenidoAmigos");
const amigosEnLinea = document.getElementById("amigosEnLinea");

/* ================= FUNCIONES AUXILIARES ================= */
function mostrarPantalla(id){
  document.querySelectorAll(".pantalla").forEach(p => p.classList.remove("activa"));
  document.getElementById(id).classList.add("activa");
}

async function obtenerNombre(uid){
  const docSnap = await getDoc(doc(db,"usuarios",uid));
  return docSnap.exists() ? docSnap.data().nombre : "Jugador";
}

async function actualizarEstadoUsuario(estado){
  if(auth.currentUser) await updateDoc(doc(db,"usuarios",auth.currentUser.uid),{estado});
}

/* ================= LOGIN / REGISTRO ================= */
document.getElementById("btnLogin").onclick = async () => {
  const email = document.getElementById("emailLogin").value;
  const password = document.getElementById("passwordLogin").value;
  try {
    const userCredential = await signInWithEmailAndPassword(auth,email,password);
    alert("¡Inicio de sesión exitoso!");
    await postLogin(userCredential.user.uid);
  } catch(e){ alert("Error login: "+e.message); }
};

document.getElementById("btnRegister").onclick = async () => {
  const email = document.getElementById("emailLogin").value;
  const password = document.getElementById("passwordLogin").value;
  const nombre = document.getElementById("nombreRegistro").value.trim();
  if(!nombre){ alert("Debes ingresar un nombre único"); return; }

  const snapshot = await getDocs(collection(db,"usuarios"));
  if(snapshot.docs.some(docSnap=>docSnap.data().nombre===nombre)){ alert("Nombre ya existe"); return; }

  try {
    const userCredential = await createUserWithEmailAndPassword(auth,email,password);
    await setDoc(doc(db,"usuarios",userCredential.user.uid),{
      nombre, estado:"en línea", amigos:[], solicitudes:[], invitaciones:[]
    });
    alert("¡Registro exitoso!");
    await postLogin(userCredential.user.uid);
  } catch(e){ alert("Error registro: "+e.message); }
};

async function postLogin(uid){
  const userDoc = doc(db,"usuarios",uid);
  const docSnap = await getDoc(userDoc);
  if(!docSnap.exists()){
    await setDoc(userDoc,{nombre:"Jugador"+uid.substring(0,4), estado:"en línea", amigos:[], solicitudes:[], invitaciones:[]});
  } else { await updateDoc(userDoc,{estado:"en línea"}); }

  mostrarPantalla("pantallaPartidas");

  // Escuchar invitaciones en tiempo real
  escucharInvitaciones();
}

/* ================= AUTO LOGIN ================= */
onAuthStateChanged(auth, async user => {
  if(user){
    await postLogin(user.uid);
  } else {
    mostrarPantalla("pantallaLogin");
  }
});

/* ================= LOGOUT ================= */
document.getElementById("btnLogout").onclick = async () => {
  if(auth.currentUser){
    await actualizarEstadoUsuario("desconectado");
    await signOut(auth);
    alert("¡Sesión cerrada!");
    mostrarPantalla("pantallaLogin");
  }
};

/* ================= CREAR / UNIR PARTIDA ================= */
document.getElementById("btnCrearPartida").onclick = async () => {
  const nombre = await obtenerNombre(auth.currentUser.uid);
  const partidaRef = await addDoc(collection(db,"partidas"),{
    tablero:["","","","","","","","",""],
    turno:"X",
    jugadorX:auth.currentUser.uid,
    jugadorO:null,
    nombreX:nombre,
    nombreO:null,
    ganador:null
  });
  partidaActualRef = partidaRef;
  jugadorXNombre.innerText = nombre;
  jugadorONombre.innerText = "Esperando...";
  codigoPartidaCreada.value = partidaRef.id;

  mostrarPantalla("pantallaJuego");
  iniciarTablero();
  escucharCambios();
  escucharMensajes();
  mostrarAmigosParaInvitar(); // Muestra amigos para invitar
};

document.getElementById("btnUnirsePartida").onclick = async () => {
  const codigo = document.getElementById("codigoPartida").value;
  await unirseAPartida(codigo);
};

async function unirseAPartida(codigo){
  const partidaRef = doc(db,"partidas",codigo);
  const docSnap = await getDoc(partidaRef);
  if(docSnap.exists() && !docSnap.data().jugadorO){
    const nombre = await obtenerNombre(auth.currentUser.uid);
    await updateDoc(partidaRef,{jugadorO:auth.currentUser.uid, nombreO:nombre});
    partidaActualRef = partidaRef;
    jugadorXNombre.innerText = docSnap.data().nombreX;
    jugadorONombre.innerText = nombre;
    codigoPartidaCreada.value = codigo;
    mostrarPantalla("pantallaJuego");
    iniciarTablero();
    escucharCambios();
    escucharMensajes();
    mostrarAmigosParaInvitar();
  } else { alert("Partida no existe o ya tiene jugador O"); }
}

/* ================= TABLERO ================= */
async function iniciarTablero(){
  if(partidaActualRef){
    const docSnap = await getDoc(partidaActualRef);
    tablero = docSnap.exists() ? docSnap.data().tablero : ["","","","","","","","",""];
    turno = docSnap.exists() ? docSnap.data().turno : "X";
  }

  tableroDiv.innerHTML="";
  for(let i=0;i<9;i++){
    const celda = document.createElement("div");
    celda.classList.add("celda");
    celda.style.width="120px";
    celda.style.height="120px";
    celda.onclick = async () => {
      if(!partidaActualRef) return;
      const data = (await getDoc(partidaActualRef)).data();
      const miTurno = (auth.currentUser.uid===data.jugadorX && data.turno==="X") || 
                      (auth.currentUser.uid===data.jugadorO && data.turno==="O");
      if(tablero[i]==="" && miTurno && !ganador){
        tablero[i] = data.turno;
        await updateDoc(partidaActualRef,{
          tablero, 
          turno:(data.turno==="X")?"O":"X"
        });
      }
    };
    tableroDiv.appendChild(celda);
  }
  actualizarTablero();
}

function actualizarTablero(){
  const celdas = tableroDiv.querySelectorAll(".celda");
  celdas.forEach((cel,i)=> cel.innerText=tablero[i]);
  verificarGanador();
}
/* ================= BOTONES SALIR / REINICIAR ================= */
// Crear botones en pantalla de juego si no existen
if(!document.getElementById("btnSalir")) {
  const divControles = document.createElement("div");
  divControles.style.marginTop = "20px";
  divControles.style.display = "flex";
  divControles.style.gap = "10px";
  
  // Botón Salir
  const btnSalir = document.createElement("button");
  btnSalir.id = "btnSalir";
  btnSalir.innerText = "Salir";
  btnSalir.style.padding = "10px 20px";
  btnSalir.style.border = "none";
  btnSalir.style.borderRadius = "10px";
  btnSalir.style.background = "linear-gradient(45deg, #ff8a00, #e52e71)";
  btnSalir.style.color = "white";
  btnSalir.style.cursor = "pointer";
  btnSalir.onclick = async () => {
    if(partidaActualRef){
      const data = (await getDoc(partidaActualRef)).data();
      if(auth.currentUser.uid === data.jugadorO){
        await updateDoc(partidaActualRef, { jugadorO: null, nombreO: null });
      } else if(auth.currentUser.uid === data.jugadorX){
        await updateDoc(partidaActualRef, { jugadorX: null, nombreX: null });
      }
    }
    partidaActualRef = null;
    tablero = ["","","","","","","","",""];
    mensajeGanadorDiv.innerText = "";
    mostrarPantalla("pantallaPartidas");
  };

  // Botón Reiniciar
  const btnReiniciar = document.createElement("button");
  btnReiniciar.id = "btnReiniciar";
  btnReiniciar.innerText = "Reiniciar partida";
  btnReiniciar.style.padding = "10px 20px";
  btnReiniciar.style.border = "none";
  btnReiniciar.style.borderRadius = "10px";
  btnReiniciar.style.background = "linear-gradient(45deg, #00c6ff, #0072ff)";
  btnReiniciar.style.color = "white";
  btnReiniciar.style.cursor = "pointer";
  btnReiniciar.onclick = async () => {
    if(!partidaActualRef) return;
    tablero = ["","","","","","","","",""];
    ganador = null;
    mensajeGanadorDiv.innerText = "";
    await updateDoc(partidaActualRef, {
      tablero,
      turno: "X",
      ganador: null
    });
    actualizarTablero();
  };

  divControles.appendChild(btnSalir);
  divControles.appendChild(btnReiniciar);
  pantallaJuego.appendChild(divControles);
}


function verificarGanador(){
  const combinaciones = [[0,1,2],[3,4,5],[6,7,8],[0,3,6],[1,4,7],[2,5,8],[0,4,8],[2,4,6]];
  ganador=null;
  const celdas = tableroDiv.querySelectorAll(".celda");
  celdas.forEach(c=>c.classList.remove("ganadora"));
  combinaciones.forEach(c=>{
    if(tablero[c[0]] && tablero[c[0]]===tablero[c[1]] && tablero[c[1]]===tablero[c[2]]){
      ganador = tablero[c[0]];
      c.forEach(idx=>celdas[idx].classList.add("ganadora"));
    }
  });
  if(ganador) mensajeGanadorDiv.innerText = "🏆 Ganador: "+ganador;
}

function escucharCambios(){
  if(!partidaActualRef) return;
  onSnapshot(partidaActualRef, docSnap=>{
    const data = docSnap.data();
    tablero = data.tablero;
    turno = data.turno;
    ganador = data.ganador;
    jugadorXNombre.innerText = data.nombreX;
    jugadorONombre.innerText = data.nombreO??"Esperando...";
    actualizarTablero();
  });
}

/* ================= CHAT ================= */
document.getElementById("btnEnviarMensaje").onclick = async () => {
  const msg = mensajeInput.value;
  if(msg && partidaActualRef){
    await addDoc(collection(partidaActualRef,"mensajes"),{
      usuario:auth.currentUser.uid,
      mensaje:msg,
      timestamp:Date.now()
    });
    mensajeInput.value="";
  }
};

function escucharMensajes(){
  if(!partidaActualRef) return;
  const q = query(collection(partidaActualRef,"mensajes"), orderBy("timestamp"));
  onSnapshot(q, async snap=>{
    chatMensajes.innerHTML="";
    for(const docSnap of snap.docs){
      const data = docSnap.data();
      let nombre = "Jugador";
      try{ const userDoc = await getDoc(doc(db,"usuarios",data.usuario));
           if(userDoc.exists()) nombre=userDoc.data().nombre;
      }catch(e){}
      const p = document.createElement("p");
      p.innerText = nombre+": "+data.mensaje;
      chatMensajes.appendChild(p);
    }
    chatMensajes.scrollTop = chatMensajes.scrollHeight;
  });
}

/* ================= AMIGOS ================= */
document.getElementById("btnAmigos").onclick = () => mostrarPantalla("pantallaAmigos");
document.getElementById("btnSeccionAñadir").onclick = () => mostrarSeccionAmigos("añadir");
document.getElementById("btnSeccionSolicitudes").onclick = () => mostrarSeccionAmigos("solicitudes");
document.getElementById("btnSeccionMisAmigos").onclick = () => mostrarSeccionAmigos("misAmigos");
document.getElementById("btnVolverPartidas3").onclick = () => mostrarPantalla("pantallaPartidas");

/* ================= FUNCIONES AMIGOS ================= */
async function mostrarSeccionAmigos(seccion){
  contenidoAmigos.innerHTML="";
  const userSnap = await getDoc(doc(db,"usuarios",auth.currentUser.uid));
  const data = userSnap.data();

  if(seccion==="añadir"){
    const input = document.createElement("input");
    input.placeholder="Nombre de amigo";
    input.style.width="70%";
    const btn = document.createElement("button");
    btn.innerText="Buscar / Añadir";
    btn.onclick = async ()=>{ 
      const nombreBuscar = input.value.trim();
      if(!nombreBuscar){ alert("Ingresa un nombre"); return; }
      const snapshot = await getDocs(collection(db,"usuarios"));
      const encontrado = snapshot.docs.find(docSnap => docSnap.data().nombre===nombreBuscar);
      if(!encontrado){ alert("Usuario no encontrado"); return; }
      const targetDoc = doc(db,"usuarios",encontrado.id);
      const targetSnap = await getDoc(targetDoc);
      const solicitudes = targetSnap.data().solicitudes || [];
      if(solicitudes.some(s => s.uid===auth.currentUser.uid)){ alert("Ya enviaste solicitud"); return; }
      solicitudes.push({nombre:data.nombre, uid:auth.currentUser.uid});
      await updateDoc(targetDoc,{solicitudes});
      alert("Solicitud enviada a "+encontrado.data().nombre);
      input.value="";
    };
    contenidoAmigos.appendChild(input);
    contenidoAmigos.appendChild(btn);
  }

  else if(seccion==="solicitudes"){
    data.solicitudes?.forEach(solic=>{
      const div = document.createElement("div");
      div.className="amigo-box";
      div.innerText=solic.nombre;
      const btnAceptar = document.createElement("button");
      btnAceptar.innerText="Aceptar";
      btnAceptar.onclick = async ()=>{
        const nuevos = data.amigos || [];
        nuevos.push({nombre:solic.nombre, uid:solic.uid});
        const nuevasSolic = data.solicitudes.filter(sol => sol.uid!==solic.uid);
        await updateDoc(doc(db,"usuarios",auth.currentUser.uid),{amigos:nuevos, solicitudes:nuevasSolic});
        const otroSnap = await getDoc(doc(db,"usuarios",solic.uid));
        if(otroSnap.exists()){
          const dataOtro = otroSnap.data();
          const amigosOtro = dataOtro.amigos || [];
          amigosOtro.push({nombre:data.nombre, uid:auth.currentUser.uid});
          await updateDoc(doc(db,"usuarios",solic.uid),{amigos:amigosOtro});
        }
        mostrarSeccionAmigos("solicitudes");
      };
      const btnRechazar = document.createElement("button");
      btnRechazar.innerText="Rechazar";
      btnRechazar.onclick = async ()=>{
        const nuevasSolic = data.solicitudes.filter(sol=>sol.uid!==solic.uid);
        await updateDoc(doc(db,"usuarios",auth.currentUser.uid),{solicitudes:nuevasSolic});
        mostrarSeccionAmigos("solicitudes");
      };
      div.appendChild(btnAceptar);
      div.appendChild(btnRechazar);
      contenidoAmigos.appendChild(div);
    });
  }

  else if(seccion==="misAmigos"){
    data.amigos?.forEach(a=>{
      const div = document.createElement("div");
      div.className="amigo-box";
      div.innerText=a.nombre;
      const btnEliminar = document.createElement("button");
      btnEliminar.innerText="Eliminar";
      btnEliminar.onclick = async ()=>{
        const nuevos = data.amigos.filter(am=>am.nombre!==a.nombre);
        await updateDoc(doc(db,"usuarios",auth.currentUser.uid),{amigos:nuevos});
        mostrarSeccionAmigos("misAmigos");
      };
      div.appendChild(btnEliminar);
      contenidoAmigos.appendChild(div);
    });
  }
}

/* ================= AMIGOS PARA INVITAR ================= */
async function mostrarAmigosParaInvitar(){
  amigosParaInvitarDiv.innerHTML = "";
  const userSnap = await getDoc(doc(db,"usuarios",auth.currentUser.uid));
  const data = userSnap.data();
  (data.amigos||[]).forEach(a=>{
    const btn = document.createElement("button");
    btn.innerText = "Invitar: "+a.nombre;
    btn.onclick = async ()=>{
      if(!partidaActualRef) return;
      const amigoSnap = await getDoc(doc(db,"usuarios",a.uid));
      if(amigoSnap.exists()){
        const invitaciones = amigoSnap.data().invitaciones||[];
        invitaciones.push({codigo:partidaActualRef.id, de:data.nombre});
        await updateDoc(doc(db,"usuarios",a.uid),{invitaciones});
        alert("Invitación enviada a "+a.nombre);
      }
    };
    amigosParaInvitarDiv.appendChild(btn);
  });
}

/* ================= ESCUCHAR INVITACIONES ================= */
async function escucharInvitaciones() {
  if (!auth.currentUser) return;
  const userDoc = doc(db, "usuarios", auth.currentUser.uid);

  onSnapshot(userDoc, snap => {
    let invitacionesDiv = document.getElementById("invitacionesPartidas");
    if (!invitacionesDiv) {
      invitacionesDiv = document.createElement("div");
      invitacionesDiv.id = "invitacionesPartidas";
      invitacionesDiv.style.marginTop = "20px";
      invitacionesDiv.style.display = "flex";
      invitacionesDiv.style.flexDirection = "column";
      invitacionesDiv.style.gap = "10px";
      pantallaPartidas.appendChild(invitacionesDiv);
    }

    invitacionesDiv.innerHTML = "";
    if (!snap.exists()) return;

    const invitaciones = snap.data().invitaciones || [];
    invitaciones.forEach(inv => {
      const div = document.createElement("div");
      div.className = "amigo-box";
      div.style.display = "flex";
      div.style.justifyContent = "space-between";
      div.style.alignItems = "center";
      div.style.padding = "10px";
      div.style.borderRadius = "10px";
      div.style.background = "rgba(0,0,0,0.3)";
      div.style.border = "2px solid";
      div.style.borderImageSlice = "1";
      div.style.borderImageSource = "linear-gradient(45deg, #ff8a00, #e52e71, #9b00ff)";
      
      const span = document.createElement("span");
      span.innerText = `Invitación de ${inv.de} | Código: ${inv.codigo}`;
      div.appendChild(span);

      const btnAceptar = document.createElement("button");
      btnAceptar.innerText = "Aceptar";
      btnAceptar.style.padding = "5px 10px";
      btnAceptar.style.border = "none";
      btnAceptar.style.borderRadius = "5px";
      btnAceptar.style.cursor = "pointer";
      btnAceptar.style.background = "linear-gradient(45deg, #ff8a00, #e52e71, #9b00ff)";
      btnAceptar.style.color = "white";
      btnAceptar.style.transition = "all 0.3s";
      btnAceptar.onmouseover = () => btnAceptar.style.transform = "scale(1.1)";
      btnAceptar.onmouseout = () => btnAceptar.style.transform = "scale(1)";

      btnAceptar.onclick = async () => {
        await unirseAPartida(inv.codigo);
        const nuevasInvitaciones = (snap.data().invitaciones || []).filter(i => i.codigo !== inv.codigo);
        await updateDoc(userDoc, { invitaciones: nuevasInvitaciones });
      };

      div.appendChild(btnAceptar);
      invitacionesDiv.appendChild(div);
    });
  });
}



