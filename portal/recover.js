(() => {

const $ = id => document.getElementById(id);

function base(){
 const v = String($("apiBase")?.value || "").trim();
 return v ? v.replace(/\/+$/,"") : "";
}

async function api(path, body){
 const res = await fetch(base()+path,{
   method:"POST",
   headers:{ "Content-Type":"application/json" },
   body:JSON.stringify(body)
 });

 const data = await res.json().catch(()=>({}));

 if(!res.ok) throw new Error(data.error || res.status);
 return data;
}

function set(el,msg){
 if(el) el.textContent = msg || "";
}

const SEND_USERNAME = "/public/recovery/username/send";
const SEND_RESET = "/public/recovery/password/send";
const COMPLETE_RESET = "/public/recovery/password/reset";

$("usernameBtn")?.addEventListener("click",async()=>{
 set($("msg1"),""); set($("err1"),"");
 try{
   await api(SEND_USERNAME,{
     orgId:$("orgId").value.trim(),
     email:$("email").value.trim().toLowerCase()
   });
   set($("msg1"),"Username sent to your email.");
 }catch(e){ set($("err1"),e.message); }
});

$("resetLinkBtn")?.addEventListener("click",async()=>{
 set($("msg1"),""); set($("err1"),"");
 try{
   await api(SEND_RESET,{
     orgId:$("orgId").value.trim(),
     email:$("email").value.trim().toLowerCase()
   });
   set($("msg1"),"Password reset link sent.");
 }catch(e){ set($("err1"),e.message); }
});

$("completeBtn")?.addEventListener("click",async()=>{
 set($("msg2"),""); set($("err2"),"");
 try{
   await api(COMPLETE_RESET,{
     orgId:$("orgId").value.trim(),
     token:$("token").value.trim(),
     newPassword:$("newPw").value
   });
   set($("msg2"),"Password updated.");
 }catch(e){ set($("err2"),e.message); }
});

$("apiBase").value = window.location.origin;

})();
