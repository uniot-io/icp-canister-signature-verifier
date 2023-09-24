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

runApp()
