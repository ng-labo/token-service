function wsdemo() {
  console.log(location.host);
  var websock = new WebSocket("wss://" + location.host + "/ws", ["token", "browser"]);
  websock.onerror = function(event) {
    console.log('WebSocket error: ', event);
  };
  websock.onopen = function (event) {
    console.log('websock.onopen');
    websock.send("Hi!");
  };
  websock.onclose = function (event) {
    console.log('websock.onclose');
    websock.close();
  };
  websock.onmessage = function (event) {
    console.log(event.data);
  }
  console.log("wsdemo end");
}
