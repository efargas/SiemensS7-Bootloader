using System.Threading;
using System.Threading.Tasks;

namespace S7.Tests.TestHelpers
{
    public class TestModbusMock
    {
        private bool _coilState;

        public Task SetCoilAsync(int coilAddress, bool state, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            _coilState = state;
            return Task.CompletedTask;
        }

        public Task<bool> GetCoilAsync(int coilAddress, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            return Task.FromResult(_coilState);
        }
    }
}