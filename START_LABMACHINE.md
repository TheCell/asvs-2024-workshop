# Start Labmachine:

OR USE THIS: https://github.com/juice-shop/juice-shop

1. Open the course project in GitLab (Something like https://gitlab.letsboot.com/asvs/asvs-241007).
2. Click on "Build > Pipelines" in the left sidebar.
3. Click on the button "Run pipeline" in the top right corner.
4. Select "owasp" option in the "LAB_START" variable dropdown.
5. Click on the "Run pipeline" button.
6. Click on the "labmachine" job.
7. Wait for the job output to show the following access information:


### Login to the "remote desktop" web ui:

Wait to see this KasmVNC access information to login to your personal remote desktop environment.
(This is just an example, the link and password in this example will not work, as they are custom generated for each user.)

```txt
=== 🔑 ACCESS INFO 🔑 ===
🤩🤩🤩🤩🤩 Kasmvnc: https://kasmvnc-??????????.letskube.ch/ 🤩🤩🤩🤩🤩
👤👤👤👤👤 Username: engineer 👤👤👤👤👤
🔑🔑🔑🔑🔑 Password: ???????????? 🔑🔑🔑🔑🔑
===
```


### URL for "juice-shop": (takes up to 5 minutes until it shows in the gitlab job logs)

Wait to see this URL to access the juice-shop. Copy the URL to either open it in the labmachine desktop environment (Firefox) or from your local browser.
(This is just an example, the link and password in this example will not work, as they are custom generated for each user.)

```txt
🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒
OWASP Juice Shop: https://juice-shop-??????????.letskube.ch/
🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒🛒
```

10. Login to the KasmVNC remote desktop.
11. Open the Firefox browser in the remote desktop.
12. Paste the juice-shop URL in the browser to access the juice-shop. (From within the remote desktop environment you can alternativel use "http://lab-worker:30042" to access the juice-shop.)
13. Use pre-installed Pentest tools to "attack" the juice-shop.