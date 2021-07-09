document.addEventListener('DOMContentLoaded', function () {
    var btn = document.getElementById('issam');
    console.log("Content loaded");
    btn.addEventListener('click', function() {
        console.log("saving...")
        let input = document.getElementById('InputEmail1').value
        chrome.storage.sync.set({ "email": input }, function(){
            console.log("email saved : "+input);
        });
   });


});


window.onload = function() {
    chrome.storage.sync.get(['email'], function(result) {
        console.log("onload")
        console.log(result);
        const email = result.email;
        document.getElementById('InputEmail1').value=email;
    });
};