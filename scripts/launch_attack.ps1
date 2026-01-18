for ($i=1; $i -le 20; $i++) {
    Start-Process python -ArgumentList "stress_test.py" -NoNewWindow
}
