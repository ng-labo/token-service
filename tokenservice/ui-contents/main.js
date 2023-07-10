// console.log("main java-script");
function get_online_agents() {
 $.get("/ask", function(data) {
    console.log(data);
    var ret = "<table><th><td>user</td></th>";
    for (var i in data.users) {
        ret += "<tr><td>" + data.users[i] + "</td></tr>";
    }
    ret += "</table>";
    console.log(ret);
    $("div.online-users").html(ret);
 });
}

function initialize_main() {
  get_online_agents();
  wsdemo();
  var intervalId = setInterval(function() {
      get_online_agents();
}, 60000);
}
