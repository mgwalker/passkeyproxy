DARK_STYLE = """
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
        background: #1a1a1a;
        color: #e0e0e0;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        padding: 20px;
    }
    .container {
        max-width: 400px;
        width: 100%;
        text-align: center;
    }
    h1 {
        font-size: 24px;
        margin-bottom: 10px;
        color: #ffffff;
    }
    p {
        margin-bottom: 30px;
        color: #b0b0b0;
        font-size: 14px;
    }
    input[type="text"] {
        width: 100%;
        padding: 12px;
        margin-bottom: 20px;
        background: #2a2a2a;
        border: 1px solid #3a3a3a;
        border-radius: 6px;
        color: #e0e0e0;
        font-size: 14px;
    }
    input[type="text"]:focus {
        outline: none;
        border-color: #4a9eff;
    }
    button {
        width: 100%;
        padding: 14px;
        background: #4a9eff;
        color: white;
        border: none;
        border-radius: 6px;
        font-size: 16px;
        font-weight: 600;
        cursor: pointer;
        transition: background 0.2s;
    }
    button:hover {
        background: #3a8eef;
    }
    button:active {
        background: #2a7edf;
    }
    .link {
        display: inline-block;
        margin-top: 20px;
        color: #4a9eff;
        text-decoration: none;
        font-size: 13px;
    }
    .link:hover {
        text-decoration: underline;
    }
    .error {
        background: #ff4444;
        color: white;
        padding: 12px;
        border-radius: 6px;
        margin-bottom: 20px;
        font-size: 14px;
    }
    .status {
        margin-top: 20px;
        font-size: 13px;
        color: #b0b0b0;
    }
    .remember-me {
        display: flex;
        align-items: center;
        justify-content: center;
        margin-bottom: 20px;
        gap: 8px;
    }
    .remember-me input[type="checkbox"] {
        width: 16px;
        height: 16px;
        cursor: pointer;
        accent-color: #4a9eff;
    }
    .remember-me label {
        font-size: 14px;
        color: #e0e0e0;
        cursor: pointer;
        user-select: none;
    }
</style>
"""
