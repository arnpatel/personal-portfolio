require([
    "dojo/dom",
    "dojo/query",
    "dojo/dom-class",
    "dojo/on", 
    "dojo/ready"
  ], function(dom, query, domClass, on, ready) {
    
  // At least one LOWERCASE character:
  var lowerCasePattern = /^(?=.*[a-z]).+$/;
  
  // At least one UPPERCASE character:
  var upperCasePattern = /^(?=.*[A-Z]).+$/;
  
  // At least one NUMBER:
  var numberPattern = /^(?=.*[\d]).+$/;
  
  // At least one SPECIAL character:
  var specialCharacterPatter = /([-+=_!@#$%^&*.,;:'\"<>/?`~\[\]\(\)\{\}\\\|\s])/;
  
  // At least 8 characters in the screen:
  var characterCountPattern = /^.{8,}/;
  
    
    ready(function(){
      var pwd = dom.byId("password");
      var lowercaseChar = query(".lowercase-char")[0];
      var uppercaseChar = query(".uppercase-char")[0];
      var numberChar = query(".number-char")[0];
      var specialChar = query(".special-char")[0];
      var _8Char = query(".8-char")[0];
      
      
      on(password, "keyup", function(e) {
        
        // Write to console. Debug
        consoleOutput(pwd);
        
        toggleRequirements(pwd, lowerCasePattern, lowercaseChar);
        toggleRequirements(pwd, upperCasePattern, uppercaseChar);
        toggleRequirements(pwd, numberPattern, numberChar);
        toggleRequirements(pwd, specialCharacterPatter, specialChar);
        toggleRequirements(pwd, characterCountPattern, _8Char);
        
        if(lowerCasePattern.test(pwd.value) && 
           upperCasePattern.test(pwd.value) &&
           numberPattern.test(pwd.value) &&
           specialCharacterPatter.test(pwd.value) &&
           characterCountPattern.test(pwd.value)
          ){
            domClass.remove(query(".success1")[0], "hide");  
           }else{ domClass.add(query(".success1")[0], "hide");   }
        
      });
         
    });
      
      function toggleRequirements(/*input*/pwd, /*RegEx*/regEx, /*element*/el){
        if(regEx.test(pwd.value) ){
          domClass.add(el, "hide");  
        }else{
          domClass.remove(el, "hide");
        }
      }
    
      // Console stuffs
      function consoleOutput(pwd){
        console.clear();
        console.log('has lowercase: ', lowerCasePattern.test(pwd.value)); 
        console.log('has uppercase: ', upperCasePattern.test(pwd.value));
        console.log('has number: ', numberPattern.test(pwd.value));
        console.log('has special character: ', specialCharacterPatter.test(pwd.value));
        console.log('at least 8 characters: ', characterCountPattern.test(pwd.value));
        console.log("----------------------------------------");
      }
    
  });