---
layout: default
title: Home
---

<section class="hero-section">
  <p class="hero-eyebrow">Security Researcher</p>
  <h1 class="hero-title">Youness Harrizi</h1>
  <p class="typewriter-text"><span id="tw-text"></span><span class="cursor">|</span></p>
  <div class="hero-cta">
    <a href="/about/" class="btn btn-primary">About Me</a>
    <a href="/contact/" class="btn btn-outline">Get In Touch</a>
  </div>
</section>

<section class="featured-research">
  <h2 class="section-heading">Featured Research</h2>
  <p class="section-sub">In-depth technical analysis on AD exploitation and Windows internals.</p>

  <div class="posts-grid">

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">NAC Bypass</span>
        <span class="post-date-label">Apr 2026</span>
      </div>
      <h3><a href="/network/nac/lateral-movement/2026/04/20/NAC-Bypass.html">Wired NAC Bypass: Getting Past 802.1x</a></h3>
      <p>Transparent bridge attack to bypass wired Network Access Control — passive listening, traffic injection, and MAC/IP spoofing.</p>
      <a href="/network/nac/lateral-movement/2026/04/20/NAC-Bypass.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">ADCS</span>
        <span class="post-date-label">Jan 2026</span>
      </div>
      <h3><a href="/active-directory/adcs/exploitation/2026/01/01/ADCS01.html">Active Directory Certificate Services (AD CS)</a></h3>
      <p>Advanced attack techniques covering ESC1, ESC5, and ESC8 misconfigurations.</p>
      <a href="/active-directory/adcs/exploitation/2026/01/01/ADCS01.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">DPAPI</span>
        <span class="post-date-label">Dec 2025</span>
      </div>
      <h3><a href="/active-directory/dpapi/credential-extraction/2025/12/15/DPAPI.html">Data Protection API (DPAPI) Deep-Dive</a></h3>
      <p>Unlocking credentials, browser secrets, and vaulted passwords using DonPAPI.</p>
      <a href="/active-directory/dpapi/credential-extraction/2025/12/15/DPAPI.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">RBCD</span>
        <span class="post-date-label">Dec 2025</span>
      </div>
      <h3><a href="/active-directory/rbcd/privilege-escalation/2025/12/01/RBCD.html">Attack Path: RBCD Exploitation</a></h3>
      <p>From BloodHound analysis to Domain Controller takeover via delegation abuse.</p>
      <a href="/active-directory/rbcd/privilege-escalation/2025/12/01/RBCD.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">ACLs</span>
        <span class="post-date-label">Nov 2025</span>
      </div>
      <h3><a href="/active-directory/acls/access-control/2025/11/01/ACLS101.html">AD 101: Access Control Lists (ACLs)</a></h3>
      <p>Understanding the foundation of AD authorization: Tokens, Security Descriptors, and ACEs.</p>
      <a href="/active-directory/acls/access-control/2025/11/01/ACLS101.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">LSASS</span>
        <span class="post-date-label">Oct 2025</span>
      </div>
      <h3><a href="/active-directory/lsass/credential-extraction/2025/10/01/lsassDump.html">LSASS Memory Dumping 2025</a></h3>
      <p>Modern techniques for credential harvesting while bypassing EDR and Credential Guard.</p>
      <a href="/active-directory/lsass/credential-extraction/2025/10/01/lsassDump.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">Domain Controllers</span>
        <span class="post-date-label">Sep 2025</span>
      </div>
      <h3><a href="/active-directory/domain-controllers/infrastructure/2025/09/01/DC101.html">AD 101: Domain Controllers</a></h3>
      <p>The heart of Active Directory: NTDS.dit, FSMO roles, and critical security considerations.</p>
      <a href="/active-directory/domain-controllers/infrastructure/2025/09/01/DC101.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">NTLM</span>
        <span class="post-date-label">Aug 2025</span>
      </div>
      <h3><a href="/ntlm/relay-attacks/lateral-movement/2025/08/04/NTLM.html">NTLM Relay: The Ultimate MITM Attack</a></h3>
      <p>Mastering relay attacks from SMB to LDAP and cross-protocol abuse.</p>
      <a href="/ntlm/relay-attacks/lateral-movement/2025/08/04/NTLM.html" class="post-card-read">Read &rarr;</a>
    </article>

    <article class="post-card">
      <div class="post-card-meta">
        <span class="post-tag">AD Fundamentals</span>
        <span class="post-date-label">Aug 2025</span>
      </div>
      <h3><a href="/active-directory/fundamentals/2025/08/01/AD101.html">AD 101: Introduction &amp; Fundamentals</a></h3>
      <p>Understanding the backbone of Windows enterprise networks and core security principals.</p>
      <a href="/active-directory/fundamentals/2025/08/01/AD101.html" class="post-card-read">Read &rarr;</a>
    </article>

  </div>

  <div style="text-align:center;margin-top:40px;">
    <a href="/blog/" class="btn btn-outline">View All Research &rarr;</a>
  </div>
</section>

<script>
  (function() {
    var phrases = [
      "Active Directory Specialist",
      "Red Teamer",
      "Penetration Tester"
    ];
    var pi = 0, ci = 0, deleting = false;
    var el = document.getElementById('tw-text');
    function tick() {
      var word = phrases[pi];
      el.textContent = deleting ? word.slice(0, ci--) : word.slice(0, ci++);
      if (!deleting && ci > word.length) { deleting = true; setTimeout(tick, 1400); return; }
      if (deleting && ci < 0) { deleting = false; pi = (pi + 1) % phrases.length; ci = 0; }
      setTimeout(tick, deleting ? 50 : 90);
    }
    tick();
  })();
</script>
