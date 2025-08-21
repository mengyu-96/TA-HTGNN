import dgl, torch

print(f"DGL version: {dgl.__version__}")
print(f"PyTorch version: {torch.__version__}")
print(f"CUDA available (PyTorch): {torch.cuda.is_available()}")
print(f"Current device: {torch.cuda.current_device()}")
print(f"Device count: {torch.cuda.device_count()}")
print(f"DGL backend: {dgl.backend.backend_name}")
print(torch.cuda.device_count())
