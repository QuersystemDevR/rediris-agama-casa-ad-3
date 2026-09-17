<#import "commons.ftlh" as com>
<@com.main>

    <#assign assets=cache.casa_assets grabLocation=(captureLocation!false)>

    <section class="pa4 shadow-4 bg-blank gray cust-section">
        <h2 class="f3 dark-blue2 tc fw7 ma0">Autenticación IRISMail</h2>
        <p class="tc mt2 mb0 i gray">
            Recuerda tener configurado tu método de doble factor (2FA). 
            Guía de como realizarlo 
            <a href="https://www.rediris.es/irismail/user.html" 
            class="link blue" 
            target="_blank" 
            rel="noopener noreferrer">
            aquí
            </a>.
        </p>

        <#if message??>
            <div style="text-align: center;">
                <p class="w5 dark-red tc pv2 ph0 ma0 f6">Autenticación Fallida</p>
            </div>
        </#if>

        <form name="login" method="post" enctype="application/x-www-form-urlencoded" class="pt2">

            <div class="field-row w-100 mt4">
                <div class="field-side" aria-hidden="true">👤</div>
                <div class="relative field-main pb2">
                    <input id="username"
                           name="username"
                           value="${username!}"
                           type="text"
                           class="focused-text w-100 pb1 dark-gray"
                           placeholder=" "
                           required>
                    <label class="focused-label-big" for="username">Mail</label>
                </div>
            </div>

            <div class="field-row w-100 mt4">
                <div class="field-side" aria-hidden="true">🔒</div>
                <div class="relative field-main pb1">
                    <input id="password"
                           name="password"
                           type="password"
                           class="focused-text w-100 pb1 dark-gray"
                           style="padding-right: 3.2rem;"
                           placeholder=" "
                           required>
                    <label class="focused-label-big" for="password">Contraseña</label>

                    <button type="button"
                            id="togglePwd"
                            class="field-toggle"
                            aria-label="Mostrar contraseña"
                            style="display:none;">👀</button>
                </div>
            </div>

            <div class="mt5 flex justify-center">
                <input type="submit" value="Iniciar sesión"
                    class="f7-cust bw0 br1 ph4 pv2 bg-bsgreen-success white hover-bsgreen-success hover-white btn cust-primary-button">
            </div>

            <input name="device" type="hidden">
            <#if grabLocation>
                <input name="location" type="hidden">
            </#if>
        </form>
    </section>

    <script src="${assets.contextPath}/scripts/ua-parser.pack-2.0.0.js"></script>
    <script>
        function attachHeaders(xhr, headers) {
            for (var i = 0; i < headers.length; i++) {
                xhr.setRequestHeader(headers[i].name, headers[i].value)
            }
        }
        
        function attachEvents(xhr, res, rej) {
            xhr.onload = () => {
                if (xhr.status < 300) return res(xhr.responseText)
                else return rej(xhr.responseText)
            }
            xhr.onerror = () => rej(xhr.statusText)
        }
        
        function genericGET(url, headers) {
          return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest()
            xhr.open("GET", url)
            if (headers) attachHeaders(xhr, headers)
            attachEvents(xhr, resolve, reject)
            xhr.send()
          })
        }
        
        function processLocation(obj, zoneProp, cityProp, stateProp, countryProp) {
            let country = obj[countryProp], state = obj[stateProp], city = obj[cityProp], zone = obj[zoneProp]
            if (!country) country = null
            if (!state) state = null
            if (!city) city = null
            if (!zone) zone = null
            return { country, state, city, zone } 
        }
    
        function fillLocationData(field) {
            field.value = JSON.stringify({ country:"col", state:"", city:"ano", zone:"t" })
        }

        function fillPlatformData(field) {
            let uapr = (new UAParser()).getResult()
            let platform = { name: uapr.browser.name, version: uapr.browser.version, 
                    osName: uapr.os.name, osVersion: uapr.os.version }                        
            field.value = JSON.stringify(platform)
            console.log(field.value)
        }

        window.onload = (event) => { 
            let f = document.forms.login                    
            if (${grabLocation?c}) fillLocationData(f.location)
            fillPlatformData(f.device)        
            
            // Toggle contraseña: mostrar SOLO mientras se mantiene pulsado
            const pwd = document.getElementById("password");
            const toggle = document.getElementById("togglePwd");

            function setToggleVisibility() {
                if (!toggle || !pwd) return;
                toggle.style.display = pwd.value && pwd.value.length > 0 ? "block" : "none";
            }

            function showPwd() { if (pwd) pwd.type = "text"; }
            function hidePwd() { if (pwd) pwd.type = "password"; }

            if (pwd && toggle) {
                setToggleVisibility();
                pwd.addEventListener("input", setToggleVisibility);

                toggle.addEventListener("mousedown", showPwd);
                toggle.addEventListener("mouseup", hidePwd);
                toggle.addEventListener("mouseleave", hidePwd);

                toggle.addEventListener("touchstart", (e) => { e.preventDefault(); showPwd(); }, { passive: false });
                toggle.addEventListener("touchend", hidePwd);
                toggle.addEventListener("touchcancel", hidePwd);

                toggle.addEventListener("keydown", (e) => {
                    if (e.key === " " || e.key === "Enter") { e.preventDefault(); showPwd(); }
                });
                toggle.addEventListener("keyup", hidePwd);
            }
        }
    </script>

    <#-- "preload" font awesome used later in selector.ftlh -->
    <script src="${assets.contextPath}/scripts/font-awesome-5.12.1.all.min.js" defer></script>

</@com.main>
