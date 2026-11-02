"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const $ = (id) => document.getElementById(id);
  let carrier = null,
    encrypted = null,
    stegoCanvas = null,
    extracted = null;
  function showPanel(mode, focus = false) {
    for (const name of ["encrypt", "decrypt"]) {
      const selected = name === mode;
      $(name + "Panel").hidden = !selected;
      $(name + "Result").hidden = !selected;
      $(name + "Tab").setAttribute("aria-selected", String(selected));
      $(name + "Tab").setAttribute("tabindex", selected ? "0" : "-1");
    }
    if (focus) $(mode + "Tab").focus();
  }
  for (const mode of ["encrypt", "decrypt"]) {
    $(mode + "Tab").addEventListener("click", () => showPanel(mode));
    $(mode + "Tab").addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key))
        return;
      event.preventDefault();
      showPanel(
        event.key === "Home"
          ? "encrypt"
          : event.key === "End"
            ? "decrypt"
            : mode === "encrypt"
              ? "decrypt"
              : "encrypt",
        true,
      );
    });
  }
  showPanel("encrypt");
  const message = (side, text, error = false) => {
    const el = $(side + "Status");
    el.textContent = text;
    el.dataset.error = String(error);
  };
  const bytesLabel = (n) =>
    n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
  function canvasFor(data) {
    const c = document.createElement("canvas");
    c.width = data.width;
    c.height = data.height;
    c.getContext("2d").putImageData(data, 0, 0);
    return c;
  }
  function preview(id, data) {
    const c = $(id);
    c.width = data.width;
    c.height = data.height;
    c.getContext("2d").putImageData(data, 0, 0);
    c.hidden = false;
  }
  function invalidate() {
    encrypted = null;
    stegoCanvas = null;
    $("cipherText").value = "";
    $("saveImage").disabled = true;
    $("copyCipher").disabled = true;
    $("sendToDecrypt").disabled = true;
    $("encryptPreview").hidden = true;
    $("outputPlaceholder").hidden = false;
    $("viewImage").disabled = true;
    $("previewCaption").textContent = "Your encrypted PNG appears here.";
  }
  function updateCapacity() {
    $("characterCount").textContent =
      `${$("plainText").value.length.toLocaleString()} characters`;
    const used = new TextEncoder().encode($("plainText").value).length + 48;
    const capacity = carrier
      ? LSBSteganography.getPayloadCapacity(carrier)
      : Math.floor((800 * 500 * 3) / 8) - 8;
    $("capacity").textContent =
      `Encrypted payload: ${bytesLabel(used)} / image capacity: ${bytesLabel(capacity)}`;
  }
  async function loadImage(file, flatten) {
    if (!file || !file.type.startsWith("image/"))
      throw new Error("Choose an image file.");
    if (file.size > 30 * 1024 * 1024)
      throw new Error("Choose an image smaller than 30 MB.");
    const url = URL.createObjectURL(file);
    try {
      const image = await new Promise((resolve, reject) => {
        const i = new Image();
        i.onload = () => resolve(i);
        i.onerror = () => reject(new Error("This image could not be opened."));
        i.src = url;
      });
      if (image.naturalWidth * image.naturalHeight > 16000000)
        throw new Error("Choose an image below 16 million pixels.");
      const c = document.createElement("canvas");
      c.width = image.naturalWidth;
      c.height = image.naturalHeight;
      const ctx = c.getContext("2d", { willReadFrequently: true });
      if (flatten) {
        ctx.fillStyle = "white";
        ctx.fillRect(0, 0, c.width, c.height);
      }
      ctx.drawImage(image, 0, 0);
      return ctx.getImageData(0, 0, c.width, c.height);
    } finally {
      URL.revokeObjectURL(url);
    }
  }
  const coverArt = loadImageAsset("images/message-cover.webp");
  function loadImageAsset(src) {
    return new Promise((resolve) => {
      const image = new Image();
      image.onload = () => resolve(image);
      image.onerror = () => resolve(null);
      image.src = src;
    });
  }
  async function defaultCarrier() {
    const c = document.createElement("canvas");
    c.width = 800;
    c.height = 500;
    const ctx = c.getContext("2d");
    const image = await coverArt;
    if (image) ctx.drawImage(image, 0, 0, 800, 500);
    else {
      ctx.fillStyle = "#244d61";
      ctx.fillRect(0, 0, 800, 500);
      ctx.fillStyle = "#934d27";
      ctx.beginPath();
      ctx.arc(600, 150, 75, 0, Math.PI * 2);
      ctx.fill();
    }
    return ctx.getImageData(0, 0, 800, 500);
  }

  async function busy(side, action) {
    $(side + "Fields").disabled = true;
    try {
      await action();
    } catch (e) {
      message(side, e.message, true);
    } finally {
      $(side + "Fields").disabled = false;
    }
  }
  $("plainText").addEventListener("input", () => {
    invalidate();
    updateCapacity();
  });
  $("encryptPassword").addEventListener("input", invalidate);
  $("coverInput").addEventListener("change", () =>
    busy("encrypt", async () => {
      invalidate();
      carrier = null;
      if ($("coverInput").files[0])
        carrier = await loadImage($("coverInput").files[0], true);
      if (carrier) {
        $("coverThumbnail").src = canvasFor(carrier).toDataURL("image/png");
        $("coverName").textContent = $("coverInput").files[0].name;
      } else {
        $("coverThumbnail").src = "images/message-cover.webp";
        $("coverName").textContent =
          "Optional: use your own PNG, JPEG or WebP.";
      }
      updateCapacity();
      message(
        "encrypt",
        carrier
          ? "Cover image loaded. Encrypt to create a new PNG."
          : "A generated cover will be used.",
      );
    }),
  );
  $("encryptButton").addEventListener("click", () =>
    busy("encrypt", async () => {
      invalidate();
      message("encrypt", "Encrypting…");
      encrypted = await CryptoEnvelope.encrypt(
        $("plainText").value,
        $("encryptPassword").value,
      );
      $("cipherText").value = CryptoEnvelope.toText(encrypted);
      $("copyCipher").disabled = false;
      $("sendToDecrypt").disabled = false;
      const image = carrier || (await defaultCarrier());
      if (encrypted.length > LSBSteganography.getPayloadCapacity(image)) {
        message(
          "encrypt",
          "Encrypted text is ready. Choose a larger cover image to save a PNG.",
          true,
        );
        return;
      }
      const stego = LSBSteganography.hideData(image, encrypted);
      // Verify the encoded payload before enabling export.
      if (
        !CryptoTextEncoder.arraysEqual(
          LSBSteganography.extractData(stego),
          encrypted,
        )
      )
        throw new Error("Image encoding verification failed.");
      stegoCanvas = canvasFor(stego);
      preview("encryptPreview", stego);
      $("saveImage").disabled = false;
      $("viewImage").disabled = false;
      $("outputPlaceholder").hidden = true;
      $("previewCaption").textContent =
        `Encrypted PNG · ${stego.width} × ${stego.height}`;
      message("encrypt", "Encrypted text and PNG are ready.");
    }),
  );
  $("saveImage").addEventListener("click", () =>
    busy("encrypt", async () => {
      if (!stegoCanvas) throw new Error("Encrypt a message first.");
      const blob = await new Promise((resolve, reject) =>
        stegoCanvas.toBlob(
          (b) => (b ? resolve(b) : reject(new Error("Unable to create PNG."))),
          "image/png",
        ),
      );
      const url = URL.createObjectURL(blob),
        a = document.createElement("a");
      a.href = url;
      a.download = "encrypted-message.png";
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    }),
  );
  $("decryptSource").addEventListener("change", () => {
    $("textSource").hidden = $("decryptSource").value !== "text";
    $("imageSource").hidden = $("decryptSource").value !== "image";
    $("plainOutput").value = "";
    $("copyPlain").disabled = true;
    message("decrypt", "Ready to decrypt.");
  });
  $("decryptText").addEventListener("input", () => {
    $("plainOutput").value = "";
    $("copyPlain").disabled = true;
  });
  $("decryptPassword").addEventListener("input", () => {
    $("plainOutput").value = "";
    $("copyPlain").disabled = true;
  });
  $("decodeInput").addEventListener("change", () =>
    busy("decrypt", async () => {
      extracted = null;
      $("decryptPreview").hidden = true;
      $("plainOutput").value = "";
      $("copyPlain").disabled = true;
      const image = await loadImage($("decodeInput").files[0], false);
      if (!LSBSteganography.containsPayload(image))
        throw new Error(
          "No hidden payload found. Use the original downloaded PNG.",
        );
      extracted = LSBSteganography.extractData(image);
      preview("decryptPreview", image);
      message(
        "decrypt",
        `Found ${bytesLabel(extracted.length)} of hidden data. Enter the password and decrypt.`,
      );
    }),
  );
  $("decryptButton").addEventListener("click", () =>
    busy("decrypt", async () => {
      $("plainOutput").value = "";
      $("copyPlain").disabled = true;
      message("decrypt", "Decrypting…");
      const payload =
        $("decryptSource").value === "image"
          ? extracted
          : CryptoEnvelope.fromText($("decryptText").value);
      if (!payload) throw new Error("Choose an encrypted PNG first.");
      const result = await CryptoEnvelope.decrypt(
        payload,
        $("decryptPassword").value,
      );
      $("plainOutput").value = result.text;
      $("copyPlain").disabled = false;
      message(
        "decrypt",
        result.legacy
          ? "Legacy message recovered. This older format has no authenticity check."
          : "Message decrypted and authenticated.",
      );
    }),
  );
  $("sendToDecrypt").addEventListener("click", () => {
    showPanel("decrypt");
    $("decryptSource").value = "text";
    $("decryptSource").dispatchEvent(new Event("change"));
    $("decryptText").value = $("cipherText").value;
    $("decryptPassword").focus();
    message("decrypt", "Encrypted text copied across. Enter its password.");
  });
  async function copy(field, side) {
    try {
      await navigator.clipboard.writeText($(field).value);
      message(side, "Copied.");
    } catch {
      $(field).focus();
      $(field).select();
      message(side, "Text selected. Press Ctrl+C (or Copy on mobile).");
    }
  }
  $("copyCipher").addEventListener("click", () =>
    copy("cipherText", "encrypt"),
  );
  $("copyPlain").addEventListener("click", () =>
    copy("plainOutput", "decrypt"),
  );
  $("clearEncrypt").addEventListener("click", () => {
    invalidate();
    carrier = null;
    $("coverInput").value = "";
    $("coverThumbnail").src = "images/message-cover.webp";
    $("coverName").textContent = "Optional: use your own PNG, JPEG or WebP.";
    $("plainText").value = "";
    $("encryptPassword").value = "";
    updateCapacity();
    message("encrypt", "Ready to encrypt.");
  });
  $("clearDecrypt").addEventListener("click", () => {
    extracted = null;
    $("decryptText").value = "";
    $("decryptPassword").value = "";
    $("plainOutput").value = "";
    $("decodeInput").value = "";
    $("decryptPreview").hidden = true;
    $("copyPlain").disabled = true;
    message("decrypt", "Ready to decrypt.");
  });
  $("useGenerated").addEventListener("click", () => {
    invalidate();
    carrier = null;
    $("coverInput").value = "";
    $("coverThumbnail").src = "images/message-cover.webp";
    $("coverName").textContent = "Generated cover selected.";
    updateCapacity();
    message("encrypt", "Generated cover selected. Encrypt to create a PNG.");
  });
  for (const button of document.querySelectorAll("[data-password]"))
    button.addEventListener("click", () => {
      const field = $(button.dataset.password),
        show = field.type === "password";
      field.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
      button.setAttribute("aria-pressed", String(show));
      button.setAttribute(
        "aria-label",
        `${show ? "Hide" : "Show"} ${button.dataset.password === "encryptPassword" ? "encryption" : "decryption"} password`,
      );
    });
  $("viewImage").addEventListener("click", async () => {
    try {
      await $("encryptPreview").requestFullscreen();
    } catch {
      message(
        "encrypt",
        "Full-screen preview is unavailable in this browser.",
        true,
      );
    }
  });
  updateCapacity();
});
