"use strict";

const form = document.getElementById("create-form");
const errorBox = document.getElementById("error");
const result = document.getElementById("result");
const submit = document.getElementById("submit");
const field = (id) => document.getElementById(id);

const FIELD_LABELS = { nom: "Nom", prenom: "Prénom", mail: "Adresse mail", matricule: "Matricule" };

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function describeError(status, body) {
  if (body && Array.isArray(body.erreurs) && body.erreurs.length) {
    return body.erreurs
      .map((item) => `${FIELD_LABELS[item.champ] || item.champ} : ${item.message}`)
      .join(" · ");
  }
  if (body && typeof body.detail === "string") return body.detail;
  return `La demande a échoué (HTTP ${status}).`;
}

// En mode démonstration, rien n'est écrit dans Active Directory : l'écran doit le dire.
fetch("healthz")
  .then((response) => response.json())
  .then((health) => { field("demo-banner").hidden = health.annuaire !== "memory"; })
  .catch(() => {});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  errorBox.hidden = true;
  if (!form.reportValidity()) return;

  submit.disabled = true;
  submit.textContent = "Création en cours…";
  try {
    const response = await fetch("api/v1/users", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${field("token").value.trim()}`,
      },
      body: JSON.stringify({
        prenom: field("prenom").value,
        nom: field("nom").value,
        mail: field("mail").value,
        matricule: field("matricule").value,
      }),
    });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
      showError(describeError(response.status, body));
      return;
    }
    field("r-nom").textContent = body.nom_affiche;
    field("r-login").textContent = body.login;
    field("r-upn").textContent = body.upn;
    field("r-matricule").textContent = body.matricule;
    field("r-dn").textContent = body.dn;
    field("r-password").textContent = body.mot_de_passe_temporaire;
    form.hidden = true;
    result.hidden = false;
  } catch {
    showError("Le service est injoignable. Vérifiez votre connexion puis réessayez.");
  } finally {
    submit.disabled = false;
    submit.textContent = "Créer le compte";
  }
});

field("copy").addEventListener("click", async () => {
  const button = field("copy");
  try {
    await navigator.clipboard.writeText(field("r-password").textContent);
    button.textContent = "Copié";
  } catch {
    button.textContent = "Copie impossible";
  }
  setTimeout(() => { button.textContent = "Copier"; }, 2000);
});

field("again").addEventListener("click", () => {
  for (const id of ["prenom", "nom", "mail", "matricule"]) field(id).value = "";
  field("r-password").textContent = "";
  result.hidden = true;
  form.hidden = false;
  field("prenom").focus();
});
