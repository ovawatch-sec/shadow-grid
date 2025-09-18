from .colors import RED, GREEN, RESET, PURPLE, BLUE, ORANGE, PINK

def disclaimer():
    return (f"""
============================================================================================================================================
        {PURPLE}Bug-Ovawatch Recon Automation Framework{RESET}
        Author: theblxckcicada
        Website: https://ovawatch.co.za
        Github: https://github.com/ovawatch-sec/bug-ovawatch
        {RED}Disclaimer: Usage of this tool implies understanding and acceptance of potential risks 
                    and the user assumes full responsibility for their actions.{RESET}
============================================================================================================================================
    """)

def banner():
	print(disclaimer())
