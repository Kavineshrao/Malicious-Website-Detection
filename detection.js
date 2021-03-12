var url = window.location.href;
var apikey = 'cf13816c8c701f1918f1f03511f96578ef93c6a3c92dce17929920d59624b9c1';

function scan(){

	var xhttp = new XMLHttpRequest();
	var vtapi = 'https://www.virustotal.com/vtapi/v2/url/scan?apikey='+apikey+'&url='+url;
	xhttp.open('POST', 'https://cors-anywhere.herokuapp.com/'+vtapi, true);
	xhttp.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
	xhttp.send();
}

function report(){

	var reportscan = new XMLHttpRequest
	reportscan.onreadystatechange = function(){
		if(this.readyState == 4 && this.status == 200) {
			//alert(reportscan.responseText);
			var vtURLResponse = JSON.parse(reportscan.responseText);
			console.log(vtURLResponse);
			var scanners = [];
			scanners = vtURLResponse.scans;
			if ((vtURLResponse.response_code == 1) && (vtURLResponse.positives != 0)) {
				for (var i in scanners) {
					if (scanners[i].detected == true || scanners[i].result == "suspicious site") {
						//alert("Dangerous");
						var confirmation = window.confirm("This website is Dangerous. Do you want to proceed?");
						if(confirmation){break;}
						else{
							window.location = "https://www.google.com/";
							break;
						}
						//break;
					}
				}							
			}
			else{
				alert("This website is good to surf.");
			}
		}
	}
	var vtapi_report = 'https://www.virustotal.com/vtapi/v2/url/report?apikey='+apikey+'&resource='+url;
	reportscan.open('GET', 'https://cors-anywhere.herokuapp.com/'+vtapi_report, true);
	reportscan.send();
}

scan();
report();