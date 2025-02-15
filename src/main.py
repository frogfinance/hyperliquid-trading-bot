import asyncio
from comm_service import CommunicationService
from screener_service import Screener
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

import config

async def main():
    logging.info("Starting bot application")
    screener = Screener()
    discordBot = CommunicationService(None, screener)

    token = config.DISCORD_TOKEN
    await discordBot.start(token)
        
asyncio.run(main())