$("#documents").change(function () {
  let fields = document.getElementById("policy-fields");
  
  while (fields.firstChild) {
    fields.removeChild(fields.firstChild);
  }
  let numInputs = $(this).val();

  if (numInputs === "one") {
    let first_name_label = document.createElement("label");
    first_name_label.innerHTML = "First Name";
    let first_name = document.createElement("input");
    first_name.type = "text";
    first_name.style = "margin-bottom:10px";

    let last_name_label = document.createElement("label");
    last_name_label.innerHTML = "Last Name";
    let last_name = document.createElement("input");
    last_name.type = "text";
    last_name.style = "margin-bottom:10px";

    let pssid_label = document.createElement("label");
    pssid_label.innerHTML = "Passport Number";
    let pssid = document.createElement("input");
    pssid.type = "text";
    pssid.style = "margin-bottom:10px";

    let submit_btn = document.createElement("input");
    submit_btn.type = "submit";
    submit_btn.style="margin-top:10px";
    submit_btn.value = "Submit";

    fields.appendChild(first_name_label);
    fields.appendChild(first_name);
    fields.appendChild(last_name_label);
    fields.appendChild(last_name);
    fields.appendChild(pssid_label);
    fields.appendChild(pssid);

    fields.appendChild(submit_btn);
  }
  else if (numInputs == "two") {

    let first_name_label = document.createElement("label");
    first_name_label.innerHTML = "First Name";
    let first_name = document.createElement("input");
    first_name.type = "text";
    first_name.name = "first_name";
    first_name.style = "margin-bottom:10px";

    let last_name_label = document.createElement("label");
    last_name_label.innerHTML = "Last Name";
    let last_name = document.createElement("input");
    last_name.type = "text";
    last_name.style = "margin-bottom:10px";

    let address_label = document.createElement("label");
    address_label.innerHTML = "Address";
    let address = document.createElement("input");
    address.type = "text";
    address.style = "margin-bottom:10px";

    let submit_btn = document.createElement("input");
    submit_btn.type = "submit";
    submit_btn.style="margin-top:10px";
    submit_btn.value = "Submit";

    fields.appendChild(first_name_label);
    fields.appendChild(first_name);
    fields.appendChild(last_name_label);
    fields.appendChild(last_name);
    fields.appendChild(address_label);
    fields.appendChild(address);

    fields.appendChild(submit_btn);
  }
});