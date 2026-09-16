"""Deterministic sysconf contract tests using the production fd.c code."""

import asyncio
import pathlib

from plugin_collection import Plugin
from maketest import StunnelAcceptConnect, LogEvent, ResultEvent


class DescriptorLimits(StunnelAcceptConnect):
    """Run build-time helpers with controlled sysconf results and errno."""

    def __init__(self, cfg, logger):
        super().__init__(cfg, logger)
        self.params.description = '321. Descriptor limits and sysconf errno'
        self.events.count = 2
        self.events.success = [r'Descriptor-limit helper .* passed']
        self.events.skip = [r'requires sysconf and non-fork threading']
        self.events.failure = ['Something went wrong']

    async def log(self, message, etype='log', level=20):
        """Route helper diagnostics into results.log."""
        await self.cfg.mainq.put(LogEvent(
            etype=etype, level=level, log=f'[fd-limits] {message}'))

    async def run_helper(self, name):
        """Run a helper with bounded waits, capturing output even on timeout."""
        helper = pathlib.Path.cwd() / name
        await self.log(f'Command: {helper}; timeout=15s; '
                       'expect seven cases and exit status 0')
        if not helper.is_file():
            raise RuntimeError(f'{helper} is missing; build with make check')
        proc = await asyncio.wait_for(asyncio.create_subprocess_exec(
            str(helper), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE), timeout=10)
        await self.log(f'{name}: PID={proc.pid}; waiting for completion')
        output = asyncio.create_task(proc.communicate())
        try:
            await asyncio.wait_for(asyncio.shield(output), timeout=15)
        finally:
            if proc.returncode is None:
                await self.log(f'{name}: killing PID={proc.pid} during cleanup')
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
            stdout, stderr = await asyncio.wait_for(output, timeout=5)
            for label, data in [('stdout', stdout), ('stderr', stderr)]:
                await self.log(f'{name} {label}:\n'
                               f'{data.decode("utf-8", errors="replace")}')
            await self.log(f'{name}: exit status={proc.returncode}')
        if proc.returncode == 77:
            await self.log('Helper requires sysconf and non-fork threading',
                           etype='output_event', level=30)
        elif proc.returncode != 0:
            raise RuntimeError(f'{name}: expected exit status 0, '
                               f'observed {proc.returncode}; see helper output')
        else:
            await self.log(f'Descriptor-limit helper {name} passed',
                           etype='output_event')

    async def test_stunnel(self, cfg):
        """Use the normal harness result and cleanup protocol."""
        task = asyncio.create_task(self.set_result())
        try:
            self.logger.info(self.params.description)
            await self.log(f"***** Start '{self.params.description}' *****", level=30)
            await self.log('Topology: local C helpers -> production get_limits; '
                           'stubbed sysconf, no sockets or TLS connections. '
                           'Testing native and forced-select limits.')
            for name in ('fd_limits_test', 'fd_limits_select_test'):
                await self.run_helper(name)
        except Exception as err:  # pylint: disable=broad-except
            await self.log(f'Something went wrong: {type(err).__name__}: {err}',
                           etype='fatal_event', level=50)
        finally:
            await self.cleanup_tasks()
            await self.expect_event(cfg.logsq, 'result_event')
            result = task.result()
            await cfg.mainq.put(ResultEvent(
                etype='set_result_event', level=20,
                log=f'[fd-limits] Test {result}', result=result))
            await self.expect_event(cfg.logsq, 'set_result_event')


class DescriptorLimitsPlugin(Plugin):
    """Register the descriptor-limit regression with the existing harness."""

    def __init__(self):
        super().__init__()
        self.description = 'Descriptor limits'

    async def perform_operation(self, cfg, logger):
        await DescriptorLimits(cfg, logger).test_stunnel(cfg)
