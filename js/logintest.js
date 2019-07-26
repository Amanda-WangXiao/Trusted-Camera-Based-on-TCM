
function login() {
  let username = document.getElementById("inputUsername");
  let password = document.getElementById("inputPassword");
  if (username == "" || password == "") {
    alert("Please fill in username and password");
  } else {
    let msg = {
      username: username,
      password: password
    };
    console.log(JSON.stringify(msg));
  }
}

var isconnected = false;

var input = document.getElementById("plain");
var passwd = document.getElementById("cipher");
var wsock;

var plainmsg = { "head": "", "record": "", "expand": "" };
plainmsg["head"] = { "tag": "MESG", "version": 65537 };
var jsonstr = JSON.stringify(plainmsg);

function mywebsockinit() {
  if (isconnected) {
    alert("已连接服务器！")
    return;
  }
  var netaddr = document.getElementById("inputServer");
  var netport = document.getElementById("inputPort");

  wsock = new WebSocket('ws://' + netaddr.value + ':' + netport.value, 'cube-wsport');

  wsock.onopen = function (e) {
    if (!isconnected) {
      isconnected = true;
      alert("连接成功！")
    }
    return;
  };
  wsock.onclose = function (e) {
  };
  wsock.onerror = function (e) {
  };
  wsock.onmessage = function (e) {
    var msg;
    msg = e.data;
    if (msg.replace(/(^s*)|(s*$)/g, "").length != 0) {
      alert(msg)
    }
  }
}

function myFunction() {
  if (!isconnected) {
    alert("连接未建立！")
    return;
  }

  var login_info = { user: input.value, passwd: passwd.value };
  var msg = new Cube_msg("CRYPTO_DEMO", "LOGIN_INFO");
  msg.addrecord(login_info);
  wsock.send(msg.output())
};