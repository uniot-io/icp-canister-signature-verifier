import '@/style.css'
import { runApp } from '@/app.js'

document.querySelector('#app').innerHTML = `
  <div>
    <div class="card">
      <button id="login-btn" type="button"> Login </button>
    </div>
    <p class="info">
      See the console for more information
    </p>
    <p class="info" id="principal-label"></p>
  </div>
`

// @dfinity/agent requires this. Can be removed once it's fixed
window.global = window

// Workaround for setting Buffer at a single and predictable place
window.Buffer = Buffer

runApp()
