var payload = window.location.hash.substr(1);
var div = document.createElement('div');
div.id = 'divEl';
document.documentElement.appendChild(div);

var divEl = document.getElementById('divEl');
divEl.innerHTML = payload;