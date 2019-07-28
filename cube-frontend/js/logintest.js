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

function login() {
  let username = document.getElementById("inputUsername").value;
  let password = document.getElementById("inputPassword").value;
  if (username == "" || password == "") {
    alert("请输入用户名和密码");
  } else {
    let login_info = {
      user: username,
      passwd: password
    };
    console.log(login_info);

    if (!isconnected) {
      alert("连接未建立！")
      return;
    }

    var msg = new Cube_msg("LOGIN_TEST", "LOGIN");
    msg.addrecord(login_info);
    wsock.send(msg.output())
  }
}