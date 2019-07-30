var isconnected = false;
var wsock;

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
    alert("Closed.");
  };
  wsock.onerror = function (e) {
    alert("Error");
  };
  wsock.onmessage = function (e) {
    var msg;
    msg = e.data;
    if (msg.replace(/(^s*)|(s*$)/g, "").length != 0) {
      alert(msg)
    }
  }
}

function register() {
  let username = document.getElementById("inputUsername").value;
  let password = document.getElementById("inputPassword").value;
  let passwordValidate = document.getElementById("inputPasswordValidate").value;
  let extras = document.getElementById("inputExtras").value;
  if (username == "" || password == "" || passwordValidate == "") {
    alert("请输入用户名和密码");
  } else if (password != passwordValidate) {
    alert("请输入相同的密码");
  } else {
    let register_info = { message: `register ${username} ${password} ${extras}` };

    if (!isconnected) {
      alert("连接未建立！")
      return;
    }

    var msg = new Cube_msg("LOGIN_TEST", "REGISTER");
    msg.addrecord(register_info);
    wsock.send(msg.output())
  }
}

function login() {
  let username = document.getElementById("inputUsername").value;
  let password = document.getElementById("inputPassword").value;
  if (username == "" || password == "") {
    alert("请输入用户名和密码");
  } else {
    let login_info = { message: `login ${username} ${password}` };

    if (!isconnected) {
      alert("连接未建立！")
      return;
    }

    var msg = new Cube_msg("LOGIN_TEST", "LOGIN");
    msg.addrecord(login_info);
    wsock.send(msg.output())
  }
}
