<#macro main>

<#assign assets=cache.casa_assets>

<!doctype html>
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="icon" href="${assets.contextPath}${assets.faviconUrl}">
        <!-- order of stylesheets is important, do not change -->
        <link rel="stylesheet" href="${assets.contextPath}/styles/bootstrap.min.css">
        <link rel="stylesheet" href="${assets.contextPath}${assets.prefix}/styles/gluu/style.css">
        <link rel="stylesheet" href="${assets.contextPath}/styles/tachyons.min.css">

        <!-- load custom branding css snippets -->
        <style>${assets.extraCss!""}</style>

        <!-- IRISMail login refinements (safe overrides) -->
        <style>
            /* =========================================================
               FLOATING LABELS (keep existing behavior, refine geometry)
               ========================================================= */

            /* Input should be the containing reference for label */
            .field-main { position: relative; }

            /* Original class kept, but adjusted to avoid spanning full width */
            .focused-label-big {
                position: absolute;
                left: 0.90rem;          /* align with input padding */
                right: auto;            /* prevent label covering full width */
                top: 0.95rem;           /* label sits inside the input */
                display: inline-flex;
                align-items: center;
                font-size: .9rem;
                cursor: text;
                transition: .14s ease-in-out;
                box-sizing: border-box;
                height: auto;           /* avoid fixed height conflicts */
                width: auto;            /* avoid spanning across container */
                pointer-events: none;
                margin-top: 0;
                padding: 0 0.25rem;
                background: #fff;       /* makes floating label look clean */
                color: rgba(0,0,0,0.60);
                transform-origin: left top;
            }

            /* When focused/valid: float above */
            .focused-text:valid + .focused-label-big,
            .focused-text:focus + .focused-label-big {
                top: -0.45rem;
                font-size: .7rem;
                color: #008495;
                transform: scale(0.95);
            }

            /* If you rely on placeholder=" " behavior, this helps in some browsers */
            .focused-text:focus::placeholder { color: transparent; }


            /* =========================================================
               FIELD ROW LAYOUT (icon left + input right)
               Fixes icon overlap / text sliding under icon
               ========================================================= */

            .field-row{
                display: flex;
                align-items: center;
                gap: 0.85rem;
                width: 100%;
            }

            .field-side{
                flex: 0 0 2.25rem;
                width: 2.25rem;
                height: 2.25rem;
                display: flex;
                align-items: center;
                justify-content: center;
                user-select: none;
                opacity: 0.95;
                font-size: 1.05rem;
                line-height: 1;
            }

            .field-main{
                flex: 1 1 auto;
                min-width: 0; /* CRITICAL in flex: prevents overflow/overlap */
            }


            /* =========================================================
               INPUT VISUAL (corporate focus / contrast)
               Works with your existing classes (tachyons etc.)
               ========================================================= */

            .focused-text{
                width: 100%;
                box-sizing: border-box;
                padding: 0.95rem 0.90rem 0.55rem 0.90rem;
                border: 1px solid rgba(0,0,0,0.18);
                border-radius: 10px;
                background: #fff;
                transition: border-color .15s ease, box-shadow .15s ease, background .15s ease;
            }

            .focused-text:hover{
                border-color: rgba(0,0,0,0.28);
            }

            .focused-text:focus{
                outline: none;
                border-color: rgba(0, 90, 140, 0.55);
                box-shadow: 0 0 0 3px rgba(0, 90, 140, 0.12);
            }

            /* Accessibility: keyboard focus */
            .focused-text:focus-visible{
                outline: 2px solid rgba(0, 90, 140, 0.55);
                outline-offset: 2px;
            }


            /* =========================================================
               PASSWORD TOGGLE (👀) - spacing + click area + focus
               ========================================================= */

            /* Ensure space for the toggle button (override inline if needed) */
            #password{
                padding-right: 3.4rem !important;
            }

            .field-toggle{
                position: absolute;
                right: 0.55rem;
                top: 50%;
                transform: translateY(-50%);
                width: 2.35rem;
                height: 2.35rem;

                display: flex;
                align-items: center;
                justify-content: center;

                border: 1px solid transparent;
                background: rgba(0,0,0,0.04);
                border-radius: 9999px;

                cursor: pointer;
                line-height: 1;
                transition: background .12s ease, border-color .12s ease, box-shadow .12s ease;
            }

            .field-toggle:hover{
                background: rgba(0,0,0,0.07);
            }

            .field-toggle:focus{
                outline: none;
            }

            .field-toggle:focus-visible{
                border-color: rgba(0, 90, 140, 0.55);
                box-shadow: 0 0 0 3px rgba(0, 90, 140, 0.12);
            }


            /* =========================================================
               AUTH ERROR TREATMENT (optional class)
               - If you later wrap message in <div class="auth-alert">, it will look good.
               - Does not break current <p> rendering.
               ========================================================= */

            .auth-alert{
                margin-top: 0.9rem;
                padding: 0.75rem 0.9rem;
                border-radius: 10px;
                border: 1px solid rgba(180, 0, 0, 0.25);
                background: rgba(180, 0, 0, 0.06);
                color: rgba(120, 0, 0, 0.95);
                font-size: 0.92rem;
                text-align: center;
            }

            .auth-alert strong{ font-weight: 700; }
            .auth-alert span{ margin-left: .35rem; font-weight: 500; }


            /* =========================================================
               SMALL POLISH (keeps corporate tone)
               ========================================================= */

            /* Slightly improve typography of headings if needed */
            h2.f3.dark-blue2{
                letter-spacing: 0.2px;
            }

            /* Ensure field rows don't collapse on very small widths */
            @media (max-width: 380px){
                .field-row{ gap: 0.65rem; }
                .field-side{ flex-basis: 2.05rem; width: 2.05rem; height: 2.05rem; }
            }
        </style>

        <script src="${assets.contextPath}/scripts/gluu/main-util.js"></script>
    </head>
    <body class="bg-near-white cust-body-rule">
        <div class="pa0 flex justify-center gray f6">
            <div class="flex flex-column min-vh-100 miw-16r mw-60r w-100 bg-washed-blue2 cust-content-rule">
                <header class="pv2 shadow-4 bg-blank cust-header">
                    <div class="w1-ns"></div>
                    <div class="w4 mh4-ns tc">
                        <img src="${assets.contextPath}${assets.logoUrl}">
                    </div>
                </header>
                <!-- grow horizontally and vertically as much as possible -->
                <div class="flex flex-column justify-between w-100 h-100">
                    <div class="flex flex-column items-center justify-center w-100 h-100 mv4">                    
                        <noscript><p class="red">Please enable javascript to use this page!</p></noscript>
                        
                        <#nested>

                    </div>
                    <footer class="pa3 f7 dark-gray shadow-4 bg-blank cust-footer-rule">
                        <div class="cust-footer-msg-rule">
                            Estás accediendo al portal de autenticación del servicio IRISmail que RedIRIS ofrece a su organización. Esta actualización forma parte de la mejora de seguridad 2026. <a href="https://www.rediris.es/irismail/auten.html" class="link blue">Aquí</a> encontraras información para comprobar la autenticidad de este acceso.
                        </div>
                    </footer>
                </div>
            </div>
        </div>
        
        <script>regenerateFooter()</script>
    </body>

</html>

</#macro>

<#macro alternative>

<form method="post" enctype="application/x-www-form-urlencoded">
    <div class="flex flex-column items-center pt3 mt2">
        <span class="f7">¿No dispone de este método de autenticación?</span>
        <button class="pa0 bw0 br0 blue hover-dark-blue underline-hover bg-transparent btn cust-link-button f7-cust"
                type="submit" id="skipped" name="skipped" value="">
            Utilizar otro método de autenticación
        </button>
    </div>
</form> 

</#macro>
