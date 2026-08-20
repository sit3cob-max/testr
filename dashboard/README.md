# Jenkins Code Review Dashboard

Copy the `jenkins` and `review-ui` folders to the root of your GitHub repository.

Configure the Jenkins Pipeline job with:
- Repository: your GitHub repository
- Branch: `*/main`
- Script path: `jenkins/Jenkinsfile`

The pipeline analyzes only files changed between the previous Jenkins commit and HEAD, writes `review-output/review.json`, builds the dark dashboard, and publishes `review-ui/index.html` with HTML Publisher.

The dashboard has no CDN or external dependency. Its stylesheet is `review-ui/assets/dashboard.css`, so it works with Jenkins default security policy.
